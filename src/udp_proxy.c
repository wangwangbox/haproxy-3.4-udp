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
#include <haproxy/list.h>
#include <haproxy/listener.h>
#include <haproxy/obj_type.h>
#include <haproxy/proxy.h>
#include <haproxy/server-t.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>

#define UDP_PROXY_SESS_TIMEOUT_MS 60000

struct udp_proxy_session {
	struct list list;
	struct listener *listener;
	struct server *srv;
	struct sockaddr_storage client;
	int fd;
	int expire;
};

static struct list udp_proxy_sessions = LIST_HEAD_INIT(udp_proxy_sessions);
__decl_spinlock(udp_proxy_lock);

static int udp_proxy_sendto(int fd, const void *buf, size_t len,
                            const struct sockaddr_storage *addr);
static void udp_proxy_delete_session(struct udp_proxy_session *sess);

static int udp_addr_match(const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b)
{
	return ipcmp(a, b, 1) == 0;
}

static struct server *udp_proxy_pick_server(struct proxy *px)
{
	struct server *srv, *fallback = NULL;

	for (srv = px->srv; srv; srv = srv->next) {
		if (srv->addr.ss_family == AF_UNSPEC)
			continue;
		if (srv->cur_state != SRV_ST_STOPPED)
			return srv;
		if (!fallback && !(srv->cur_admin & SRV_ADMF_MAINT))
			fallback = srv;
	}

	return fallback;
}

static void udp_proxy_prune_locked(void)
{
	struct udp_proxy_session *sess, *back;

	list_for_each_entry_safe(sess, back, &udp_proxy_sessions, list) {
		if (tick_is_expired(sess->expire, now_ms))
			udp_proxy_delete_session(sess);
	}
}

static struct udp_proxy_session *udp_proxy_find_client_locked(struct listener *l,
                                                             const struct sockaddr_storage *client)
{
	struct udp_proxy_session *sess;

	list_for_each_entry(sess, &udp_proxy_sessions, list) {
		if (sess->listener == l && udp_addr_match(&sess->client, client))
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
	LIST_DEL_INIT(&sess->list);
	if (sess->fd >= 0) {
		fd_delete(sess->fd);
		close(sess->fd);
	}
	free(sess);
}

static struct udp_proxy_session *udp_proxy_get_session(struct listener *l,
                                                       const struct sockaddr_storage *client,
                                                       struct server *srv)
{
	struct udp_proxy_session *sess;

	HA_SPIN_LOCK(OTHER_LOCK, &udp_proxy_lock);
	udp_proxy_prune_locked();
	sess = udp_proxy_find_client_locked(l, client);
	if (!sess) {
		sess = calloc(1, sizeof(*sess));
		if (sess) {
			LIST_INIT(&sess->list);
			sess->listener = l;
			memcpy(&sess->client, client, sizeof(*client));
			sess->fd = -1;
			sess->srv = srv;
			if (!udp_proxy_connect_session(sess)) {
				free(sess);
				sess = NULL;
			}
			else
				LIST_APPEND(&udp_proxy_sessions, &sess->list);
		}
	}
	if (sess) {
		sess->srv = srv;
		sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
	}
	HA_SPIN_UNLOCK(OTHER_LOCK, &udp_proxy_lock);

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

void udp_proxy_fd_handler(int fd)
{
	struct listener *l = objt_listener(fdtab[fd].owner);
	struct proxy *px;
	struct buffer *buf = get_trash_chunk();
	int max_accept;

	BUG_ON(!l);
	px = l->bind_conf->frontend;

	if (!(fdtab[fd].state & FD_POLL_IN))
		return;
	if (!fd_recv_ready(fd))
		return;

	max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;
	do {
		struct sockaddr_storage saddr = {0};
		socklen_t saddrlen = sizeof(saddr);
		struct udp_proxy_session *sess;
		struct server *srv;
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

		srv = udp_proxy_pick_server(px);
		if (!srv)
			continue;
		sess = udp_proxy_get_session(l, &saddr, srv);
		if (!sess)
			continue;
		if (send(sess->fd, buf->area, ret, 0) < 0) {
			HA_SPIN_LOCK(OTHER_LOCK, &udp_proxy_lock);
			udp_proxy_delete_session(sess);
			HA_SPIN_UNLOCK(OTHER_LOCK, &udp_proxy_lock);
		}
	} while (--max_accept);
}
