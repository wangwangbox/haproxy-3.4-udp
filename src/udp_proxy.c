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
#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/backend.h>
#include <haproxy/backend-t.h>
#include <haproxy/buf-t.h>
#include <haproxy/chunk.h>
#include <haproxy/check.h>
#include <haproxy/fd.h>
#include <haproxy/global.h>
#include <haproxy/init.h>
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
#include <haproxy/resolvers.h>
#include <haproxy/server-t.h>
#include <haproxy/session-t.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/vars.h>

#define UDP_PROXY_SESS_TIMEOUT_MS 60000
#define UDP_PROXY_GC_INTERVAL_MS 1000
#define UDP_PROXY_HASH_BITS 12
#define UDP_PROXY_HASH_SIZE (1U << UDP_PROXY_HASH_BITS)
#define UDP_PROXY_HASH_MASK (UDP_PROXY_HASH_SIZE - 1)
#define UDP_PROXY_GC_BUCKETS_PER_RUN 4
#define UDP_PROXY_MAX_RECV_PER_RUN 64

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
static struct task *udp_proxy_gc_tasks[MAX_THREADS];
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

static int udp_addr_is_any(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET)
		return ((const struct sockaddr_in *)addr)->sin_addr.s_addr == INADDR_ANY;
	if (addr->ss_family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(&((const struct sockaddr_in6 *)addr)->sin6_addr);
	return 0;
}

static int udp_proxy_would_loop(const struct udp_proxy_session *sess,
				const struct sockaddr_storage *server_addr,
				uint16_t server_port)
{
	const struct receiver *rx = &sess->listener->rx;

	if (get_host_port(&rx->addr) != server_port)
		return 0;

	if (rx->addr.ss_family != server_addr->ss_family)
		return 0;

	if (ipcmp(&rx->addr, server_addr, 0) == 0)
		return 1;

	if (!udp_addr_is_any(&rx->addr))
		return 0;

	return addr_is_local(rx->settings->netns, server_addr) == 1;
}

static void udp_proxy_eval_resolve_rules(struct proxy *px, struct session *sess,
                                         struct stream *strm)
{
	struct act_rule *rule;

	list_for_each_entry(rule, &px->tcp_req.inspect_rules, list) {
		if (rule->check_ptr != check_action_do_resolve)
			continue;
		if (rule->cond &&
		    !acl_match_cond(rule->cond, px, sess, strm,
		                    SMP_OPT_DIR_REQ | SMP_OPT_FINAL))
			continue;

		EXEC_CTX_WITH_RET(rule->exec_ctx,
		                  rule->action_ptr(rule, px, sess, strm,
		                                   ACT_OPT_FINAL | ACT_OPT_FINAL_EARLY | ACT_OPT_FIRST));
	}
}

static struct proxy *udp_proxy_eval_switching_rules(struct proxy *px,
                                                    const struct sockaddr_storage *client)
{
	struct switching_rule *rule;
	struct sockaddr_storage src;
	struct session sess;
	struct stream strm;
	struct proxy *backend = NULL;

	if (LIST_ISEMPTY(&px->tcp_req.inspect_rules) && LIST_ISEMPTY(&px->switching_rules))
		return px;

	memset(&sess, 0, sizeof(sess));
	memset(&strm, 0, sizeof(strm));
	src = *client;

	sess.fe = px;
	sess.listener = NULL;
	sess.src = &src;
	LIST_INIT(&sess.priv_conns);
	vars_init_head(&sess.vars, SCOPE_SESS);

	strm.obj_type = OBJ_TYPE_STREAM;
	strm.sess = &sess;
	strm.be = px;
	strm.rules_exp = TICK_ETERNITY;
	vars_init_head(&strm.vars_txn, SCOPE_TXN);
	vars_init_head(&strm.vars_reqres, SCOPE_REQ);

	udp_proxy_eval_resolve_rules(px, &sess, &strm);

	list_for_each_entry(rule, &px->switching_rules, list) {
		if (rule->cond &&
		    !acl_match_cond(rule->cond, px, &sess, &strm,
		                    SMP_OPT_DIR_REQ | SMP_OPT_FINAL))
			continue;
		if (rule->dynamic)
			continue;
		if (rule->be.backend && be_is_eligible(rule->be.backend)) {
			backend = rule->be.backend;
			break;
		}
	}

	vars_prune(&strm.vars_reqres, &sess, &strm);
	vars_prune(&strm.vars_txn, &sess, &strm);
	vars_prune_per_sess(&sess.vars);

	return backend ? backend : px;
}

static int udp_proxy_srv_usable(const struct server *srv)
{
	if (srv->addr.ss_family == AF_UNSPEC)
		return 0;
	if (srv->cur_admin & SRV_ADMF_MAINT)
		return 0;
	if (srv->cur_state == SRV_ST_STOPPED)
		return 0;
	return 1;
}

static struct server *udp_proxy_pick_lb_server(struct proxy *px,
                                               const struct sockaddr_storage *client,
                                               const void *payload, size_t payload_len)
{
	struct server *srv = NULL;
	struct stream strm = { };

	if (!px->lbprm.tot_weight)
		return NULL;

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

static void udp_proxy_gc_all(struct udp_proxy_shard *shard)
{
	unsigned int i;

	for (i = 0; i < UDP_PROXY_HASH_SIZE; i++)
		udp_proxy_prune_bucket(shard, i);
}

static struct task *udp_proxy_gc_task(struct task *t, void *context, unsigned int state)
{
	struct udp_proxy_shard *shard = context;

	if (_HA_ATOMIC_LOAD(&udp_proxy_nb_sessions) > 0)
		udp_proxy_gc_all(shard);

	t->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_GC_INTERVAL_MS));
	return t;
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
	int max_recv = UDP_PROXY_MAX_RECV_PER_RUN;

	if (!sess)
		return;
	if (!(fdtab[fd].state & FD_POLL_IN))
		return;
	if (!fd_recv_ready(fd))
		return;

	do {
		ssize_t ret;

		ret = recv(fd, buf->area, buf->size, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(fd);
				return;
			}

			/* Connected UDP sockets report asynchronous ICMP errors here.
			 * Leaving such an FD registered makes the poller wake up forever.
			 */
			health_adjust(sess->srv, HANA_STATUS_L4_ERR);
			udp_proxy_delete_session(sess);
			return;
		}

		health_adjust(sess->srv, HANA_STATUS_L4_OK);
		sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
		udp_proxy_sendto(sess->listener->rx.fd, buf->area, ret, &sess->client);
	} while (--max_recv);
}

static int udp_proxy_connect_session(struct udp_proxy_session *sess)
{
	struct sockaddr_storage addr;
	uint16_t port;
	int fd;

	HA_SPIN_LOCK(SERVER_LOCK, &sess->srv->lock);
	addr = sess->srv->addr;
	port = sess->srv->svc_port;
	HA_SPIN_UNLOCK(SERVER_LOCK, &sess->srv->lock);

	if (addr.ss_family == AF_UNSPEC)
		return 0;
	if (udp_proxy_would_loop(sess, &addr, port))
		return 0;

	fd = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
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

	set_host_port(&addr, port);
	if (connect(fd, (struct sockaddr *)&addr, get_addr_len(&addr)) == -1) {
		close(fd);
		return 0;
	}

	if (fd_set_nonblock(fd) == -1 || fd_set_cloexec(fd) == -1) {
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
		struct proxy *px;

		px = udp_proxy_eval_switching_rules(l->bind_conf->frontend, client);
		srv = udp_proxy_pick_lb_server(px, client, payload, payload_len);
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

	health_adjust(sess->srv, HANA_STATUS_L4_ERR);
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

static int udp_proxy_thread_init(void)
{
	udp_proxy_shard_init(&udp_proxy_shards[tid]);
	udp_proxy_gc_tasks[tid] = task_new_here();
	if (!udp_proxy_gc_tasks[tid]) {
		ha_alert("failed to allocate UDP proxy GC task.\n");
		return 0;
	}

	udp_proxy_gc_tasks[tid]->process = udp_proxy_gc_task;
	udp_proxy_gc_tasks[tid]->context = &udp_proxy_shards[tid];
	task_schedule(udp_proxy_gc_tasks[tid],
	              tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_GC_INTERVAL_MS)));

	return 1;
}

REGISTER_PER_THREAD_INIT(udp_proxy_thread_init);
