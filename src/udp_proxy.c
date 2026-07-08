/*
 * UDP proxying for regular listen/frontend sections.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/backend-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/chunk.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/lb_chash.h>
#include <haproxy/lb_fas.h>
#include <haproxy/lb_fwlc.h>
#include <haproxy/lb_fwrr.h>
#include <haproxy/lb_map.h>
#include <haproxy/lb_ss.h>
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

#define UDP_PROXY_SESS_TIMEOUT_MS 60000
#define UDP_PROXY_HASH_BITS 12
#define UDP_PROXY_HASH_SIZE (1U << UDP_PROXY_HASH_BITS)
#define UDP_PROXY_HASH_MASK (UDP_PROXY_HASH_SIZE - 1)
#define UDP_PROXY_GC_BUCKETS_PER_RUN 4

struct udp_proxy_session {
	struct list by_hash;
	struct listener *listener;
	struct server *srv;
	struct sockaddr_storage client;
	unsigned int hash;
	int fd;
	int expire;
};

struct udp_proxy_shard {
	struct list buckets[UDP_PROXY_HASH_SIZE];
	unsigned int gc_bucket;
	int initialized;
};

static struct udp_proxy_shard udp_proxy_shards[MAX_THREADS];
static int udp_proxy_nb_sessions;

static int udp_proxy_sendto(int fd, const void *buf, size_t len,
                            const struct sockaddr_storage *addr);
static void udp_proxy_delete_session(struct udp_proxy_session *sess);
static int udp_proxy_send_connected(struct udp_proxy_session *sess,
                                    const void *buf, size_t len);

static int udp_proxy_session_limit(const struct listener *l)
{
	const struct proxy *px = l->bind_conf->frontend;

	if (l->bind_conf->maxconn > 0)
		return l->bind_conf->maxconn;
	if (px->maxconn > 0)
		return px->maxconn;
	return global.maxconn;
}

static void udp_proxy_shard_init(struct udp_proxy_shard *shard)
{
	unsigned int i;

	if (likely(shard->initialized))
		return;

	for (i = 0; i < UDP_PROXY_HASH_SIZE; i++)
		LIST_INIT(&shard->buckets[i]);

	shard->gc_bucket = 0;
	shard->initialized = 1;
}

static unsigned int udp_hash_mix(unsigned int hash, unsigned int value)
{
	hash ^= value;
	hash *= 16777619U;
	return hash;
}

static unsigned int udp_hash_bytes(unsigned int hash, const void *data, size_t len)
{
	const unsigned char *ptr = data;

	while (len--)
		hash = udp_hash_mix(hash, *ptr++);

	return hash;
}

static unsigned int udp_proxy_hash_key(const struct listener *l,
                                       const struct sockaddr_storage *addr)
{
	unsigned int hash = 2166136261U;

	hash = udp_hash_bytes(hash, &l, sizeof(l));
	hash = udp_hash_mix(hash, addr->ss_family);

	switch (addr->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

		hash = udp_hash_bytes(hash, &sin->sin_addr, sizeof(sin->sin_addr));
		hash = udp_hash_bytes(hash, &sin->sin_port, sizeof(sin->sin_port));
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

		hash = udp_hash_bytes(hash, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
		hash = udp_hash_bytes(hash, &sin6->sin6_port, sizeof(sin6->sin6_port));
		hash = udp_hash_bytes(hash, &sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id));
		break;
	}
	default:
		hash = udp_hash_bytes(hash, addr, get_addr_len(addr));
		break;
	}

	return hash;
}

static int udp_addr_match(const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b)
{
	return ipcmp(a, b, 1) == 0;
}

static int udp_proxy_srv_usable(const struct server *srv)
{
	if (srv->addr.ss_family == AF_UNSPEC)
		return 0;
	if (srv->cur_admin & SRV_ADMF_MAINT)
		return 0;
	if ((srv->check.state & CHK_ST_CONFIGURED) && srv->cur_state == SRV_ST_STOPPED)
		return 0;
	return 1;
}

static struct server *udp_proxy_fallback_server(struct proxy *px)
{
	struct server *srv;

	for (srv = px->srv; srv; srv = srv->next) {
		if (udp_proxy_srv_usable(srv))
			return srv;
	}

	return NULL;
}

static struct server *udp_proxy_pick_lb_server(struct proxy *px,
                                               const struct sockaddr_storage *client,
                                               const void *payload, size_t payload_len)
{
	struct server *srv = NULL;
	struct stream strm = { };

	if (!px->lbprm.tot_weight)
		return udp_proxy_fallback_server(px);

	switch (px->lbprm.algo & BE_LB_LKUP) {
	case BE_LB_LKUP_RRTREE:
		srv = fwrr_get_next_server(px, NULL);
		break;

	case BE_LB_LKUP_FSTREE:
		srv = fas_get_next_server(px, NULL);
		break;

	case BE_LB_LKUP_LCTREE:
		srv = fwlc_get_next_server(px, NULL);
		break;

	case BE_LB_LKUP_CHTREE:
	case BE_LB_LKUP_MAP:
		if ((px->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_RR) {
			if ((px->lbprm.algo & BE_LB_PARM) == BE_LB_RR_RANDOM) {
				strm.be = px;
				srv = get_server_rnd(&strm, NULL);
			}
			else
				srv = map_get_server_rr(px, NULL);
			break;
		}

		if ((px->lbprm.algo & BE_LB_KIND) != BE_LB_KIND_HI)
			break;

		switch (px->lbprm.algo & BE_LB_PARM) {
		case BE_LB_HASH_SRC:
			if (client->ss_family == AF_INET) {
				srv = get_server_sh(px,
				                    (void *)&((const struct sockaddr_in *)client)->sin_addr,
				                    4, NULL);
			}
			else if (client->ss_family == AF_INET6) {
				srv = get_server_sh(px,
				                    (void *)&((const struct sockaddr_in6 *)client)->sin6_addr,
				                    16, NULL);
			}
			break;

		case BE_LB_HASH_RDP:
		case BE_LB_HASH_SMP:
			if (payload_len)
				srv = get_server_sh(px, payload, payload_len, NULL);
			break;
		}

		if (!srv) {
			if ((px->lbprm.algo & BE_LB_LKUP) == BE_LB_LKUP_CHTREE)
				srv = chash_get_next_server(px, NULL);
			else
				srv = map_get_server_rr(px, NULL);
		}
		break;

	default:
		if ((px->lbprm.algo & BE_LB_KIND) == BE_LB_KIND_SA &&
		    (px->lbprm.algo & BE_LB_PARM) == BE_LB_SA_SS)
			srv = ss_get_server(px);
		break;
	}

	return srv;
}

static void udp_proxy_take_server(struct server *srv)
{
	_HA_ATOMIC_INC(&srv->served);
	_HA_ATOMIC_INC(&srv->proxy->served);
	__ha_barrier_atomic_store();
	if (srv->proxy->lbprm.ops && srv->proxy->lbprm.ops->server_take_conn)
		srv->proxy->lbprm.ops->server_take_conn(srv);
	if (srv->proxy->be_counters.shared.tg)
		_HA_ATOMIC_INC(&srv->proxy->be_counters.shared.tg[tgid - 1]->cum_lbconn);
	if (srv->counters.shared.tg)
		_HA_ATOMIC_INC(&srv->counters.shared.tg[tgid - 1]->cum_lbconn);
}

static void udp_proxy_drop_server(struct server *srv)
{
	_HA_ATOMIC_DEC(&srv->proxy->served);
	_HA_ATOMIC_DEC(&srv->served);
	__ha_barrier_atomic_store();
	if (srv->proxy->lbprm.ops && srv->proxy->lbprm.ops->server_drop_conn)
		srv->proxy->lbprm.ops->server_drop_conn(srv);
}

static void udp_proxy_prune_bucket(struct udp_proxy_shard *shard, unsigned int bucket)
{
	struct udp_proxy_session *sess, *back;

	list_for_each_entry_safe(sess, back, &shard->buckets[bucket], by_hash) {
		if (tick_is_expired(sess->expire, now_ms))
			udp_proxy_delete_session(sess);
	}
}

static void udp_proxy_gc(struct udp_proxy_shard *shard)
{
	unsigned int i;

	for (i = 0; i < UDP_PROXY_GC_BUCKETS_PER_RUN; i++) {
		udp_proxy_prune_bucket(shard, shard->gc_bucket);
		shard->gc_bucket = (shard->gc_bucket + 1) & UDP_PROXY_HASH_MASK;
	}
}

static struct udp_proxy_session *udp_proxy_find_client(struct udp_proxy_shard *shard,
                                                       struct listener *l,
                                                       const struct sockaddr_storage *client,
                                                       unsigned int hash)
{
	struct udp_proxy_session *sess;

	list_for_each_entry(sess, &shard->buckets[hash & UDP_PROXY_HASH_MASK], by_hash) {
		if (sess->hash == hash &&
		    sess->listener == l &&
		    udp_addr_match(&sess->client, client))
			return sess;
	}

	return NULL;
}

static void udp_proxy_session_fd_handler(int fd)
{
	struct udp_proxy_session *sess = fdtab[fd].owner;
	struct buffer *buf = get_trash_chunk();

	if (!sess)
		return;
	if (!(fdtab[fd].state & FD_POLL_IN))
		return;
	if (!fd_recv_ready(fd))
		return;

	while (1) {
		ssize_t ret;

		ret = recv(fd, buf->area, buf->size, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				fd_cant_recv(fd);
			break;
		}

		sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
		udp_proxy_sendto(sess->listener->rx.fd, buf->area, ret, &sess->client);
	}
}

static int udp_proxy_connect_session(struct udp_proxy_session *sess)
{
	struct sockaddr_storage addr;
	int fd;

	fd = socket(sess->srv->addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
		return 0;
	if (fd >= global.maxsock) {
		close(fd);
		return 0;
	}

	if (global.tune.backend_rcvbuf)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.backend_rcvbuf,
		           sizeof(global.tune.backend_rcvbuf));
	if (global.tune.backend_sndbuf)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.backend_sndbuf,
		           sizeof(global.tune.backend_sndbuf));

	addr = sess->srv->addr;
	set_host_port(&addr, sess->srv->svc_port);
	if (connect(fd, (struct sockaddr *)&addr, get_addr_len(&addr)) == -1) {
		close(fd);
		return 0;
	}

	if (fd_set_nonblock(fd) == -1) {
		close(fd);
		return 0;
	}

	sess->fd = fd;
	fd_insert(fd, sess, udp_proxy_session_fd_handler, tgid, ti->ltid_bit);
	fd_want_recv(fd);
	return 1;
}

static void udp_proxy_delete_session(struct udp_proxy_session *sess)
{
	LIST_DEL_INIT(&sess->by_hash);
	if (sess->fd >= 0) {
		fd_delete(sess->fd);
		sess->fd = -1;
	}
	if (sess->srv)
		udp_proxy_drop_server(sess->srv);
	_HA_ATOMIC_DEC(&udp_proxy_nb_sessions);
	free(sess);
}

static struct udp_proxy_session *udp_proxy_get_session(struct listener *l,
                                                       const struct sockaddr_storage *client,
                                                       const void *payload, size_t payload_len)
{
	struct udp_proxy_shard *shard = &udp_proxy_shards[tid];
	struct udp_proxy_session *sess;
	struct server *srv;
	unsigned int hash;

	udp_proxy_shard_init(shard);
	udp_proxy_gc(shard);

	hash = udp_proxy_hash_key(l, client);
	udp_proxy_prune_bucket(shard, hash & UDP_PROXY_HASH_MASK);
	sess = udp_proxy_find_client(shard, l, client, hash);
	if (sess && !udp_proxy_srv_usable(sess->srv)) {
		udp_proxy_delete_session(sess);
		sess = NULL;
	}
	if (!sess) {
		int limit = udp_proxy_session_limit(l);

		srv = udp_proxy_pick_lb_server(l->bind_conf->frontend, client,
		                               payload, payload_len);
		if (!srv)
			return NULL;

		if (limit > 0 && _HA_ATOMIC_LOAD(&udp_proxy_nb_sessions) >= limit)
			return NULL;

		sess = calloc(1, sizeof(*sess));
		if (sess) {
			LIST_INIT(&sess->by_hash);
			sess->listener = l;
			memcpy(&sess->client, client, sizeof(*client));
			sess->hash = hash;
			sess->fd = -1;
			sess->srv = srv;
			if (!udp_proxy_connect_session(sess)) {
				free(sess);
				sess = NULL;
			}
			else {
				udp_proxy_take_server(srv);
				_HA_ATOMIC_INC(&udp_proxy_nb_sessions);
				LIST_APPEND(&shard->buckets[hash & UDP_PROXY_HASH_MASK],
				            &sess->by_hash);
			}
		}
	}
	if (sess) {
		sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
	}

	return sess;
}

static int udp_proxy_sendto(int fd, const void *buf, size_t len,
                            const struct sockaddr_storage *addr)
{
	ssize_t ret;

	ret = sendto(fd, buf, len, 0, (const struct sockaddr *)addr,
	             get_addr_len(addr));
	return ret == (ssize_t)len;
}

static int udp_proxy_send_connected(struct udp_proxy_session *sess,
                                    const void *buf, size_t len)
{
	ssize_t ret;

	do {
		ret = send(sess->fd, buf, len, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret == (ssize_t)len)
		return 1;

	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;

	udp_proxy_delete_session(sess);
	return -1;
}

void udp_proxy_fd_handler(int fd)
{
	struct listener *l = objt_listener(fdtab[fd].owner);
	struct buffer *buf = get_trash_chunk();
	int max_accept;

	BUG_ON(!l);

	if (!(fdtab[fd].state & FD_POLL_IN))
		return;
	if (!fd_recv_ready(fd))
		return;

	max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;
	do {
		struct sockaddr_storage saddr = {0};
		socklen_t saddrlen = sizeof(saddr);
		struct udp_proxy_session *sess;
		ssize_t ret;

		ret = recvfrom(fd, buf->area, buf->size, 0,
		               (struct sockaddr *)&saddr, &saddrlen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				fd_cant_recv(fd);
			break;
		}

		sess = udp_proxy_get_session(l, &saddr, buf->area, ret);
		if (!sess)
			continue;
		udp_proxy_send_connected(sess, buf->area, ret);
	} while (--max_accept);
}
