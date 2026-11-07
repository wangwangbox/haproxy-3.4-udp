/*
 * UDP proxying for regular listen/frontend sections.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <haproxy/api.h>
#include <haproxy/acl.h>
#include <haproxy/action.h>
#include <haproxy/backend.h>
#include <haproxy/backend-t.h>
#include <haproxy/buf.h>
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
#include <haproxy/pool.h>
#include <haproxy/proxy.h>
#include <haproxy/queue.h>
#include <haproxy/resolvers.h>
#include <haproxy/sample.h>
#include <haproxy/server-t.h>
#include <haproxy/session-t.h>
#include <haproxy/stream-t.h>
#include <haproxy/task.h>
#include <haproxy/thread.h>
#include <haproxy/time.h>
#include <haproxy/ticks.h>
#include <haproxy/tools.h>
#include <haproxy/udp_proxy.h>
#include <haproxy/vars.h>

#define UDP_PROXY_SESS_TIMEOUT_MS 60000
#define UDP_PROXY_GC_INTERVAL_MS 1000
#define UDP_PROXY_HASH_BITS 12
#define UDP_PROXY_HASH_SIZE (1U << UDP_PROXY_HASH_BITS)
#define UDP_PROXY_HASH_MASK (UDP_PROXY_HASH_SIZE - 1)
#define UDP_PROXY_GC_BUCKETS_PER_RUN 4
#define UDP_PROXY_MAX_RECV_PER_RUN 64

/* Large enough for any UDP payload over IPv4/IPv6 (no jumbograms), so that
 * datagrams are never truncated.
 */
#define UDP_PROXY_RXBUF_SIZE 65536

/* do-resolve support */
#define UDP_PROXY_RESOLV_MAX_PER_THREAD 1024   /* max cached names per thread */
#define UDP_PROXY_RESOLV_TIMEOUT_MS     10000  /* give up on a resolution after this */
#define UDP_PROXY_RESOLV_DEF_HOLD_MS    10000  /* result lifetime if "hold valid" is 0 */
#define UDP_PROXY_RESOLV_NEG_HOLD_MS    1000   /* failure lifetime if "hold nx" is 0 */
#define UDP_PROXY_RESOLV_IDLE_MS        60000  /* forget names unused for that long */

/* rules evaluation results */
#define UDP_RULES_ACCEPT   0
#define UDP_RULES_REJECT  -1
#define UDP_RULES_PENDING -2   /* waiting for a DNS resolution, drop for now */

/* states of a do-resolve cache entry */
#define UDP_RESOLV_NONE    0   /* first resolution still running */
#define UDP_RESOLV_VALID   1   /* <ip> holds the last resolved address */
#define UDP_RESOLV_FAILED  2   /* last resolution failed */

struct udp_proxy_session {
	struct list by_hash;
	struct listener *listener;
	struct server *srv;
	struct sockaddr_storage client;   /* client address and port */
	struct sockaddr_storage local;    /* address the client contacted, AF_UNSPEC if not known */
	struct sockaddr_storage srv_addr; /* address and port the socket is connected to */
	unsigned int hash;
	int fd;
	int expire;
};

/* A name resolved by a "do-resolve" rule. The result is kept per thread and
 * refreshed in the background. While a resolution runs, a heap-allocated fake
 * stream owns the DNS requester so that the resolution is not aborted.
 */
struct udp_proxy_resolv {
	struct list list;
	struct act_rule *rule;
	char *name;
	size_t name_len;
	struct stream *owner;
	struct task *task;
	int state;
	int expire;
	int last_use;
	int family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
};

struct udp_proxy_shard {
	struct list buckets[UDP_PROXY_HASH_SIZE];
	struct list resolv;
	unsigned int nb_resolv;
	unsigned int gc_bucket;
	int initialized;
};

static struct udp_proxy_shard udp_proxy_shards[MAX_THREADS];
static struct task *udp_proxy_gc_tasks[MAX_THREADS];
static int udp_proxy_nb_sessions;
static int udp_proxy_used;
static THREAD_LOCAL char *udp_proxy_rxbuf;

static void udp_proxy_delete_session(struct udp_proxy_session *sess);

static void udp_proxy_shard_init(struct udp_proxy_shard *shard)
{
	unsigned int i;

	if (likely(shard->initialized))
		return;

	for (i = 0; i < UDP_PROXY_HASH_SIZE; i++)
		LIST_INIT(&shard->buckets[i]);
	LIST_INIT(&shard->resolv);

	shard->nb_resolv = 0;
	shard->gc_bucket = 0;
	shard->initialized = 1;
}

/***************************************************************************
 * addresses
 ***************************************************************************/

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

static unsigned int udp_hash_addr(unsigned int hash, const struct sockaddr_storage *addr,
                                  int with_port)
{
	hash = udp_hash_mix(hash, addr->ss_family);

	switch (addr->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

		hash = udp_hash_bytes(hash, &sin->sin_addr, sizeof(sin->sin_addr));
		if (with_port)
			hash = udp_hash_bytes(hash, &sin->sin_port, sizeof(sin->sin_port));
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

		hash = udp_hash_bytes(hash, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
		if (with_port)
			hash = udp_hash_bytes(hash, &sin6->sin6_port, sizeof(sin6->sin6_port));
		hash = udp_hash_bytes(hash, &sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id));
		break;
	}
	default:
		break;
	}

	return hash;
}

/* a flow is identified by the listener, the client address and port, and the
 * local address the client contacted (relevant on wildcard binds).
 */
static unsigned int udp_proxy_hash_key(const struct listener *l,
                                       const struct sockaddr_storage *client,
                                       const struct sockaddr_storage *local)
{
	unsigned int hash = 2166136261U;

	hash = udp_hash_bytes(hash, &l, sizeof(l));
	hash = udp_hash_addr(hash, client, 1);
	hash = udp_hash_addr(hash, local, 0);
	return hash;
}

static int udp_addr_match(const struct sockaddr_storage *a,
                          const struct sockaddr_storage *b)
{
	return ipcmp(a, b, 1) == 0;
}

static int udp_local_match(const struct sockaddr_storage *a,
                           const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return 0;
	if (a->ss_family == AF_UNSPEC)
		return 1;
	return ipcmp(a, b, 0) == 0;
}

/* Receives one datagram from listener socket <fd> into <buf>. The peer address
 * goes to <from>. When the socket passes packet info (wildcard binds), <to>
 * receives the local address the datagram was sent to, with <l>'s port.
 * Otherwise <to> is AF_UNSPEC. Returns the recvmsg() result.
 */
static ssize_t udp_proxy_recv(int fd, struct listener *l, void *buf, size_t len,
                              struct sockaddr_storage *from,
                              struct sockaddr_storage *to)
{
	union pktinfo {
#ifdef IP_PKTINFO
		struct in_pktinfo in;
#else
		struct in_addr addr;
#endif
#ifdef IPV6_RECVPKTINFO
		struct in6_pktinfo in6;
#endif
	};
	union {
		char buf[CMSG_SPACE(sizeof(union pktinfo))];
		struct cmsghdr align;
	} cdata;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec vec;
	ssize_t ret;

	vec.iov_base = buf;
	vec.iov_len  = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name       = from;
	msg.msg_namelen    = sizeof(*from);
	msg.msg_iov        = &vec;
	msg.msg_iovlen     = 1;
	msg.msg_control    = cdata.buf;
	msg.msg_controllen = sizeof(cdata.buf);

	memset(to, 0, sizeof(*to));
	to->ss_family = AF_UNSPEC;

	do {
		ret = recvmsg(fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 || !(l->rx.flags & RX_F_PASS_PKTINFO))
		return ret;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case IPPROTO_IP:
#if defined(IP_PKTINFO)
			if (cmsg->cmsg_type == IP_PKTINFO) {
				struct sockaddr_in *in = (struct sockaddr_in *)to;
				struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);

				in->sin_family = AF_INET;
				in->sin_addr = info->ipi_addr;
				in->sin_port = get_net_port(&l->rx.addr);
			}
#elif defined(IP_RECVDSTADDR)
			if (cmsg->cmsg_type == IP_RECVDSTADDR) {
				struct sockaddr_in *in = (struct sockaddr_in *)to;
				struct in_addr *info = (struct in_addr *)CMSG_DATA(cmsg);

				in->sin_family = AF_INET;
				in->sin_addr.s_addr = info->s_addr;
				in->sin_port = get_net_port(&l->rx.addr);
			}
#endif
			break;

		case IPPROTO_IPV6:
#ifdef IPV6_RECVPKTINFO
			if (cmsg->cmsg_type == IPV6_PKTINFO) {
				struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)to;
				struct in6_pktinfo *info6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

				in6->sin6_family = AF_INET6;
				memcpy(&in6->sin6_addr, &info6->ipi6_addr, sizeof(in6->sin6_addr));
				in6->sin6_port = get_net_port(&l->rx.addr);
			}
#endif
			break;
		}
	}

	return ret;
}

/* Sends <buf> to <to> from listener socket <fd>. If <from> is known, it is
 * forced as the source address so that the client sees the reply coming from
 * the address it contacted. Returns 1 if the whole datagram was sent.
 */
static int udp_proxy_send_reply(int fd, const void *buf, size_t len,
                                const struct sockaddr_storage *to,
                                const struct sockaddr_storage *from)
{
	union {
#ifdef IP_PKTINFO
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif
#ifdef IPV6_RECVPKTINFO
		char buf6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
		char bufaddr[CMSG_SPACE(sizeof(struct in_addr))];
		struct cmsghdr align;
	} cdata;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec vec;
	ssize_t ret;

	vec.iov_base = (void *)buf;
	vec.iov_len  = len;

	memset(&cdata, 0, sizeof(cdata));
	memset(&msg, 0, sizeof(msg));
	msg.msg_name    = (void *)to;
	msg.msg_namelen = get_addr_len(to);
	msg.msg_iov     = &vec;
	msg.msg_iovlen  = 1;

	switch (from->ss_family) {
	case AF_INET:
#if defined(IP_PKTINFO)
		msg.msg_control    = &cdata;
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type  = IP_PKTINFO;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
		((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst =
			((const struct sockaddr_in *)from)->sin_addr;
#elif defined(IP_RECVDSTADDR)
		msg.msg_control    = &cdata;
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type  = IP_SENDSRCADDR;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_addr));
		memcpy(CMSG_DATA(cmsg), &((const struct sockaddr_in *)from)->sin_addr,
		       sizeof(struct in_addr));
#endif
		break;

	case AF_INET6:
#ifdef IPV6_RECVPKTINFO
		msg.msg_control    = &cdata;
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type  = IPV6_PKTINFO;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
		memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
		       &((const struct sockaddr_in6 *)from)->sin6_addr,
		       sizeof(struct in6_addr));
#endif
		break;

	default:
		break;
	}

	do {
		ret = sendmsg(fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	return ret == (ssize_t)len;
}

/* Computes in <out> the address and port used to reach <srv> for a flow that
 * arrived on listener <l> towards local address <local> (AF_UNSPEC if not
 * known). Like for TCP, a server without port or with a +/-offset follows the
 * port the client contacted, and a 0.0.0.0 server address follows the local
 * address the client contacted. <srv>'s address is read under its lock when
 * <lock> is set. Returns 1 on success, 0 if no usable address could be built.
 */
static int udp_proxy_srv_target(struct server *srv, const struct listener *l,
                                const struct sockaddr_storage *local,
                                struct sockaddr_storage *out, int lock)
{
	const struct sockaddr_storage *dst;
	int port;

	if (lock)
		HA_SPIN_LOCK(SERVER_LOCK, &srv->lock);
	*out = srv->addr;
	port = srv->svc_port;
	if (lock)
		HA_SPIN_UNLOCK(SERVER_LOCK, &srv->lock);

	if (out->ss_family != AF_INET && out->ss_family != AF_INET6)
		return 0;

	dst = (local->ss_family != AF_UNSPEC) ? local : &l->rx.addr;

	if (!is_inet_addr(out)) {
		if (dst->ss_family != out->ss_family || !is_inet_addr(dst))
			return 0;
		*out = *dst;
	}

	if (srv->flags & SRV_F_MAPPORTS)
		port += get_host_port(&l->rx.addr);

	port &= 0xffff;
	if (!port)
		return 0;

	set_host_port(out, port);
	return 1;
}

/***************************************************************************
 * do-resolve
 ***************************************************************************/

static void udp_proxy_resolv_set_failed(struct udp_proxy_resolv *res,
                                        const struct resolvers *resolvers)
{
	int hold = resolvers ? resolvers->hold.nx : 0;

	res->state = UDP_RESOLV_FAILED;
	res->expire = tick_add(now_ms, MS_TO_TICKS(hold ? hold : UDP_PROXY_RESOLV_NEG_HOLD_MS));
}

/* Extracts the address from a valid resolution. Must be called with the
 * resolvers lock held.
 */
static void udp_proxy_resolv_collect(struct udp_proxy_resolv *res,
                                     struct resolv_resolution *resolution)
{
	struct resolvers *resolvers = resolution->resolvers;
	short family = 0;
	void *ip = NULL;

	resolv_get_ip_from_response(&resolution->response, res->rule->arg.resolv.opts,
	                            NULL, 0, &ip, &family, NULL);

	if (ip && family == AF_INET) {
		memcpy(&res->ip.v4, ip, sizeof(res->ip.v4));
	}
	else if (ip && family == AF_INET6) {
		memcpy(&res->ip.v6, ip, sizeof(res->ip.v6));
	}
	else {
		udp_proxy_resolv_set_failed(res, resolvers);
		return;
	}

	res->family = family;
	res->state = UDP_RESOLV_VALID;
	res->expire = tick_add(now_ms, MS_TO_TICKS(resolvers->hold.valid ?
	                                           resolvers->hold.valid :
	                                           UDP_PROXY_RESOLV_DEF_HOLD_MS));
}

/* Releases the fake stream owning the DNS requester of <res>. Must be called
 * with the resolvers lock held.
 */
static void udp_proxy_resolv_release(struct udp_proxy_resolv *res)
{
	struct stream *s = res->owner;

	if (!s)
		return;

	ha_free(&s->resolv_ctx.hostname_dn);
	s->resolv_ctx.hostname_dn_len = 0;
	if (s->resolv_ctx.requester) {
		resolv_unlink_resolution(s->resolv_ctx.requester);
		pool_free(resolv_requester_pool, s->resolv_ctx.requester);
		s->resolv_ctx.requester = NULL;
	}
	free(s);
	res->owner = NULL;
}

/* Starts (or refreshes) the resolution of <res>'s name. A fresh cached
 * response is used immediately. Otherwise the resolution runs in the
 * background and res->task is woken up when it completes.
 */
static void udp_proxy_resolv_start(struct udp_proxy_resolv *res)
{
	struct resolvers *resolvers = res->rule->arg.resolv.resolvers;
	struct buffer *tmp = get_trash_chunk();
	struct resolv_resolution *resolution;
	struct resolv_requester *req;
	struct stream *s;
	int dn_len;

	if (res->owner)
		return;

	if (!resolvers)
		goto fail;

	dn_len = resolv_str_to_dn_label(res->name, res->name_len, tmp->area, tmp->size);
	if (dn_len <= 0)
		goto fail;

	s = calloc(1, sizeof(*s));
	if (!s)
		goto fail;

	s->obj_type = OBJ_TYPE_STREAM;
	s->task = res->task;
	s->resolv_ctx.parent = res->rule;
	s->resolv_ctx.hostname_dn = strdup(tmp->area);
	s->resolv_ctx.hostname_dn_len = dn_len;
	if (!s->resolv_ctx.hostname_dn) {
		free(s);
		goto fail;
	}

	res->owner = s;

	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	if (resolv_link_resolution(s, OBJ_TYPE_STREAM, 0) < 0 ||
	    !(req = s->resolv_ctx.requester) || !req->resolution) {
		udp_proxy_resolv_release(res);
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
		goto fail;
	}

	resolution = req->resolution;
	if (resolution->status == RSLV_STATUS_VALID && resolvers->t &&
	    tick_isset(resolution->last_resolution) &&
	    !tick_is_expired(tick_add(resolution->last_resolution, resolvers->hold.valid), now_ms)) {
		/* fresh cached response */
		udp_proxy_resolv_collect(res, resolution);
		udp_proxy_resolv_release(res);
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
		return;
	}

	resolv_trigger_resolution(req);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);

	res->task->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_RESOLV_TIMEOUT_MS));
	task_queue(res->task);
	return;

 fail:
	udp_proxy_resolv_set_failed(res, resolvers);
}

/* Woken up by the resolvers when the resolution of a name completes, or on
 * timeout.
 */
static struct task *udp_proxy_resolv_task(struct task *t, void *context, unsigned int state)
{
	struct udp_proxy_resolv *res = context;
	struct resolvers *resolvers = res->rule->arg.resolv.resolvers;
	struct resolv_resolution *resolution;
	int expired = tick_is_expired(t->expire, now_ms);

	if (!res->owner) {
		t->expire = TICK_ETERNITY;
		return t;
	}

	HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);

	resolution = res->owner->resolv_ctx.requester ?
	             res->owner->resolv_ctx.requester->resolution : NULL;

	if (resolution && !expired &&
	    (resolution->step == RSLV_STEP_RUNNING || resolution->status == RSLV_STATUS_NONE)) {
		/* not finished yet */
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
		return t;
	}

	if (resolution && resolution->status == RSLV_STATUS_VALID)
		udp_proxy_resolv_collect(res, resolution);
	else
		udp_proxy_resolv_set_failed(res, resolvers);

	udp_proxy_resolv_release(res);
	HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);

	t->expire = TICK_ETERNITY;
	return t;
}

static struct udp_proxy_resolv *udp_proxy_resolv_new(struct udp_proxy_shard *shard,
                                                     struct act_rule *rule,
                                                     const char *name, size_t len)
{
	struct udp_proxy_resolv *res;

	res = calloc(1, sizeof(*res));
	if (!res)
		return NULL;

	res->name = malloc(len + 1);
	res->task = task_new_here();
	if (!res->name || !res->task) {
		free(res->name);
		if (res->task)
			task_destroy(res->task);
		free(res);
		return NULL;
	}

	memcpy(res->name, name, len);
	res->name[len] = 0;
	res->name_len = len;
	res->rule = rule;
	res->state = UDP_RESOLV_NONE;
	res->expire = TICK_ETERNITY;
	res->last_use = now_ms;
	res->task->process = udp_proxy_resolv_task;
	res->task->context = res;
	res->task->expire = TICK_ETERNITY;

	LIST_APPEND(&shard->resolv, &res->list);
	shard->nb_resolv++;
	return res;
}

static void udp_proxy_resolv_free(struct udp_proxy_shard *shard, struct udp_proxy_resolv *res)
{
	if (res->owner) {
		struct resolvers *resolvers = res->rule->arg.resolv.resolvers;

		HA_SPIN_LOCK(DNS_LOCK, &resolvers->lock);
		udp_proxy_resolv_release(res);
		HA_SPIN_UNLOCK(DNS_LOCK, &resolvers->lock);
	}
	LIST_DELETE(&res->list);
	shard->nb_resolv--;
	task_destroy(res->task);
	free(res->name);
	free(res);
}

static void udp_proxy_resolv_gc(struct udp_proxy_shard *shard)
{
	struct udp_proxy_resolv *res, *back;

	list_for_each_entry_safe(res, back, &shard->resolv, list) {
		if (res->owner)
			continue;
		if (!tick_is_expired(tick_add(res->last_use, MS_TO_TICKS(UDP_PROXY_RESOLV_IDLE_MS)), now_ms))
			continue;
		if (tick_isset(res->expire) && !tick_is_expired(res->expire, now_ms))
			continue;
		udp_proxy_resolv_free(shard, res);
	}
}

static void udp_proxy_resolv_set_var(struct udp_proxy_resolv *res, struct proxy *px,
                                     struct session *sess, struct stream *strm)
{
	struct sample smp;

	memset(&smp, 0, sizeof(smp));
	smp.px = px;
	smp.sess = sess;
	smp.strm = strm;

	if (res->family == AF_INET) {
		smp.data.type = SMP_T_IPV4;
		smp.data.u.ipv4 = res->ip.v4;
	}
	else {
		smp.data.type = SMP_T_IPV6;
		smp.data.u.ipv6 = res->ip.v6;
	}

	vars_set_by_name(res->rule->arg.resolv.varname, strlen(res->rule->arg.resolv.varname), &smp);
}

/* Executes a "do-resolve" rule for a new flow. The variable is set when an
 * address is known. Returns 1 to continue rules processing, or 0 when the
 * very first resolution of this name is still running, in which case the
 * datagram must be dropped (the client's next one will get the result).
 * Expired results are refreshed in the background while still being used.
 */
static int udp_proxy_do_resolve(struct act_rule *rule, struct proxy *px,
                                struct session *sess, struct stream *strm)
{
	struct udp_proxy_shard *shard = &udp_proxy_shards[tid];
	struct udp_proxy_resolv *res;
	struct sample *smp;
	const char *name;
	size_t len;

	smp = sample_fetch_as_type(px, sess, strm, SMP_OPT_DIR_REQ | SMP_OPT_FINAL,
	                           rule->arg.resolv.expr, SMP_T_STR);
	if (!smp || !smp->data.u.str.data)
		return 1;

	name = smp->data.u.str.area;
	len = smp->data.u.str.data;

	list_for_each_entry(res, &shard->resolv, list) {
		if (res->rule == rule && res->name_len == len && memcmp(res->name, name, len) == 0)
			goto found;
	}

	/* bound the memory used by names derived from client traffic */
	if (shard->nb_resolv >= UDP_PROXY_RESOLV_MAX_PER_THREAD)
		return 1;

	res = udp_proxy_resolv_new(shard, rule, name, len);
	if (!res)
		return 1;

	udp_proxy_resolv_start(res);

 found:
	res->last_use = now_ms;

	if (res->state == UDP_RESOLV_NONE)
		return 0;

	if (tick_is_expired(res->expire, now_ms))
		udp_proxy_resolv_start(res);

	if (res->state == UDP_RESOLV_VALID)
		udp_proxy_resolv_set_var(res, px, sess, strm);

	return 1;
}

/***************************************************************************
 * rules and server selection
 ***************************************************************************/

/* Returns non-zero if <rule> can be executed for UDP flows. Other actions
 * need a real connection or stream and are ignored (reported at boot).
 */
static int udp_proxy_rule_supported(const struct act_rule *rule)
{
	if (!rule->action_ptr)
		return rule->action == ACT_ACTION_ALLOW || rule->action == ACT_ACTION_DENY;

	if (rule->check_ptr == check_action_do_resolve)
		return 1;

	if (rule->kw && rule->kw->kw &&
	    (strcmp(rule->kw->kw, "set-var") == 0 || strcmp(rule->kw->kw, "unset-var") == 0))
		return 1;

	return 0;
}

static int udp_proxy_exec_rules(struct list *rules, struct proxy *px,
                                struct session *sess, struct stream *strm)
{
	struct act_rule *rule;

	list_for_each_entry(rule, rules, list) {
		if (!udp_proxy_rule_supported(rule))
			continue;

		if (!acl_match_cond(rule->cond, px, sess, strm, SMP_OPT_DIR_REQ | SMP_OPT_FINAL))
			continue;

		if (rule->check_ptr == check_action_do_resolve) {
			if (!udp_proxy_do_resolve(rule, px, sess, strm))
				return UDP_RULES_PENDING;
			continue;
		}

		if (rule->action_ptr) {
			switch (EXEC_CTX_WITH_RET(rule->exec_ctx,
			                          rule->action_ptr(rule, px, sess, strm,
			                                           ACT_OPT_FINAL | ACT_OPT_FIRST))) {
			case ACT_RET_CONT:
			case ACT_RET_YIELD:
				continue;
			case ACT_RET_STOP:
			case ACT_RET_DONE:
				return UDP_RULES_ACCEPT;
			default:
				return UDP_RULES_REJECT;
			}
		}

		if (rule->action == ACT_ACTION_ALLOW)
			return UDP_RULES_ACCEPT;
		if (rule->action == ACT_ACTION_DENY)
			return UDP_RULES_REJECT;
	}

	return UDP_RULES_ACCEPT;
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

/* Picks a server of backend <px>. <strm> is the evaluation stream, with the
 * first datagram in its request channel.
 */
static struct server *udp_proxy_pick_lb_server(struct proxy *px, struct stream *strm,
                                               const struct sockaddr_storage *client)
{
	struct server *srv = NULL;

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
			if ((px->lbprm.algo & BE_LB_PARM) == BE_LB_RR_RANDOM)
				srv = get_server_rnd(strm, NULL);
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
			srv = get_server_rch(strm, NULL);
			break;

		case BE_LB_HASH_SMP:
			srv = get_server_expr(strm, NULL);
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

/* Runs the frontend's rules for a new flow, selects the backend and picks a
 * server. <local> is the address the client contacted (AF_UNSPEC if unknown)
 * and <payload> the first datagram, made available to the rules and to the
 * load balancing algorithms through the request channel. Returns the server,
 * or NULL if the datagram must be dropped.
 */
static struct server *udp_proxy_select_server(struct listener *l,
                                              const struct sockaddr_storage *client,
                                              const struct sockaddr_storage *local,
                                              char *payload, size_t payload_len)
{
	struct proxy *fe = l->bind_conf->frontend;
	struct proxy *backend = NULL;
	struct switching_rule *rule;
	struct sockaddr_storage src, dst;
	struct session sess;
	struct stream strm;
	struct server *srv = NULL;
	int ret;

	memset(&sess, 0, sizeof(sess));
	memset(&strm, 0, sizeof(strm));
	src = *client;
	dst = (local->ss_family != AF_UNSPEC) ? *local : l->rx.addr;

	sess.fe = fe;
	sess.listener = l;
	sess.src = &src;
	sess.dst = &dst;
	LIST_INIT(&sess.priv_conns);
	vars_init_head(&sess.vars, SCOPE_SESS);

	strm.obj_type = OBJ_TYPE_STREAM;
	strm.sess = &sess;
	strm.be = fe;
	strm.rules_exp = TICK_ETERNITY;
	strm.req.buf = b_make(payload, UDP_PROXY_RXBUF_SIZE, 0, payload_len);
	vars_init_head(&strm.vars_txn, SCOPE_TXN);
	vars_init_head(&strm.vars_reqres, SCOPE_REQ);

	/* same order as for TCP: connection, session then content rules */
	ret = udp_proxy_exec_rules(&fe->tcp_req.l4_rules, fe, &sess, NULL);
	if (ret == UDP_RULES_ACCEPT)
		ret = udp_proxy_exec_rules(&fe->tcp_req.l5_rules, fe, &sess, NULL);
	if (ret == UDP_RULES_ACCEPT)
		ret = udp_proxy_exec_rules(&fe->tcp_req.inspect_rules, fe, &sess, &strm);
	if (ret != UDP_RULES_ACCEPT)
		goto out;

	list_for_each_entry(rule, &fe->switching_rules, list) {
		if (rule->dynamic)
			continue; /* not supported, reported at boot */
		if (!acl_match_cond(rule->cond, fe, &sess, &strm, SMP_OPT_DIR_REQ | SMP_OPT_FINAL))
			continue;
		if (rule->be.backend && be_is_eligible(rule->be.backend)) {
			backend = rule->be.backend;
			break;
		}
	}

	/* same fallback as TCP: default_backend, then the frontend itself */
	if (!backend && fe->defbe.be && be_is_eligible(fe->defbe.be))
		backend = fe->defbe.be;
	if (!backend)
		backend = fe;

	strm.be = backend;
	srv = udp_proxy_pick_lb_server(backend, &strm, client);
	if (srv && (!udp_proxy_srv_usable(srv) ||
	            (srv->maxconn && srv->cur_sess >= srv_dynamic_maxconn(srv))))
		srv = NULL;

 out:
	vars_prune(&strm.vars_reqres, &sess, &strm);
	vars_prune(&strm.vars_txn, &sess, &strm);
	vars_prune_per_sess(&sess.vars);
	return srv;
}

/***************************************************************************
 * sessions
 ***************************************************************************/

static int udp_proxy_session_allowed(struct listener *l)
{
	const struct proxy *fe = l->bind_conf->frontend;

	/* l->nbconn is not used: UDP never goes through listener_release(),
	 * so resume_listener() could otherwise leave the listener disabled.
	 */
	if (l->bind_conf->maxconn && _HA_ATOMIC_LOAD(&l->udp_nbsess) >= l->bind_conf->maxconn)
		return 0;
	if (fe->maxconn && _HA_ATOMIC_LOAD(&fe->feconn) >= fe->maxconn)
		return 0;
	if (global.maxconn && _HA_ATOMIC_LOAD(&udp_proxy_nb_sessions) >= global.maxconn)
		return 0;
	return 1;
}

static void udp_proxy_take_server(struct udp_proxy_session *sess)
{
	struct server *srv = sess->srv;
	struct proxy *fe = sess->listener->bind_conf->frontend;

	_HA_ATOMIC_INC(&udp_proxy_nb_sessions);
	_HA_ATOMIC_INC(&sess->listener->udp_nbsess);
	_HA_ATOMIC_INC(&fe->feconn);

	_HA_ATOMIC_INC(&srv->per_tgrp[tgid - 1].nb_strm);
	_HA_ATOMIC_INC(&srv->cur_sess);
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

static void udp_proxy_drop_server(struct udp_proxy_session *sess)
{
	struct server *srv = sess->srv;
	struct proxy *fe = sess->listener->bind_conf->frontend;

	_HA_ATOMIC_DEC(&srv->proxy->served);
	_HA_ATOMIC_DEC(&srv->served);
	_HA_ATOMIC_DEC(&srv->cur_sess);
	_HA_ATOMIC_DEC(&srv->per_tgrp[tgid - 1].nb_strm);
	__ha_barrier_atomic_store();
	if (srv->proxy->lbprm.ops && srv->proxy->lbprm.ops->server_drop_conn)
		srv->proxy->lbprm.ops->server_drop_conn(srv);

	_HA_ATOMIC_DEC(&fe->feconn);
	_HA_ATOMIC_DEC(&sess->listener->udp_nbsess);
	_HA_ATOMIC_DEC(&udp_proxy_nb_sessions);
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
	if (shard->nb_resolv)
		udp_proxy_resolv_gc(shard);

	t->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_GC_INTERVAL_MS));
	return t;
}

static struct udp_proxy_session *udp_proxy_find_client(struct udp_proxy_shard *shard,
                                                       struct listener *l,
                                                       const struct sockaddr_storage *client,
                                                       const struct sockaddr_storage *local,
                                                       unsigned int hash)
{
	struct udp_proxy_session *sess;

	list_for_each_entry(sess, &shard->buckets[hash & UDP_PROXY_HASH_MASK], by_hash) {
		if (sess->hash == hash &&
		    sess->listener == l &&
		    udp_addr_match(&sess->client, client) &&
		    udp_local_match(&sess->local, local))
			return sess;
	}

	return NULL;
}

/* Returns non-zero if the server of <sess> is no longer reachable at the
 * address the session socket is connected to (DNS or CLI address change).
 * The server address is read without its lock: a torn read can only cause
 * a harmless reconnection.
 */
static int udp_proxy_srv_moved(const struct udp_proxy_session *sess)
{
	struct sockaddr_storage cur;

	if (!udp_proxy_srv_target(sess->srv, sess->listener, &sess->local, &cur, 0))
		return 1;
	return ipcmp(&cur, &sess->srv_addr, 1) != 0;
}

static void udp_proxy_session_fd_handler(int fd)
{
	struct udp_proxy_session *sess = fdtab[fd].owner;
	char *buf = udp_proxy_rxbuf;
	int max_recv = UDP_PROXY_MAX_RECV_PER_RUN;

	if (!sess || !buf)
		return;
	/* an ICMP error on a connected UDP socket is only reported as an
	 * error (no POLL_IN), and must be consumed by recv() or the poller
	 * would report it forever.
	 */
	if (!(fdtab[fd].state & (FD_POLL_IN | FD_POLL_ERR | FD_POLL_HUP)))
		return;
	if (!fd_recv_ready(fd))
		return;

	do {
		ssize_t ret;

		ret = recv(fd, buf, UDP_PROXY_RXBUF_SIZE, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				fd_cant_recv(fd);
				return;
			}

			/* Connected UDP sockets report asynchronous ICMP errors here. */
			health_adjust(sess->srv, HANA_STATUS_L4_ERR);
			udp_proxy_delete_session(sess);
			return;
		}

		health_adjust(sess->srv, HANA_STATUS_L4_OK);
		sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
		udp_proxy_send_reply(sess->listener->rx.fd, buf, ret, &sess->client, &sess->local);
	} while (--max_recv);
}

static int udp_proxy_connect_session(struct udp_proxy_session *sess)
{
	struct server *srv = sess->srv;
	struct conn_src *src = NULL;
	int fd;

	if (!udp_proxy_srv_target(srv, sess->listener, &sess->local, &sess->srv_addr, 1))
		return 0;

	fd = socket(sess->srv_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
		return 0;
	if (fd >= global.maxsock) {
		close(fd);
		return 0;
	}

	if (fd_set_nonblock(fd) == -1 || fd_set_cloexec(fd) == -1) {
		close(fd);
		return 0;
	}

	if (global.tune.backend_rcvbuf)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &global.tune.backend_rcvbuf,
		           sizeof(global.tune.backend_rcvbuf));
	if (global.tune.backend_sndbuf)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &global.tune.backend_sndbuf,
		           sizeof(global.tune.backend_sndbuf));

	/* "source" on the server, otherwise on the backend */
	if (srv->conn_src.opts & CO_SRC_BIND)
		src = &srv->conn_src;
	else if (srv->proxy->conn_src.opts & CO_SRC_BIND)
		src = &srv->proxy->conn_src;

	if (src && src->source_addr.ss_family == sess->srv_addr.ss_family) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (bind(fd, (struct sockaddr *)&src->source_addr,
		         get_addr_len(&src->source_addr)) == -1) {
			close(fd);
			return 0;
		}
	}

	if (connect(fd, (struct sockaddr *)&sess->srv_addr, get_addr_len(&sess->srv_addr)) == -1) {
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
		udp_proxy_drop_server(sess);
	free(sess);
}

static struct udp_proxy_session *udp_proxy_get_session(struct listener *l,
                                                       const struct sockaddr_storage *client,
                                                       const struct sockaddr_storage *local,
                                                       char *payload, size_t payload_len)
{
	struct udp_proxy_shard *shard = &udp_proxy_shards[tid];
	struct udp_proxy_session *sess;
	struct server *srv;
	unsigned int hash;

	udp_proxy_shard_init(shard);
	udp_proxy_gc(shard);

	hash = udp_proxy_hash_key(l, client, local);
	udp_proxy_prune_bucket(shard, hash & UDP_PROXY_HASH_MASK);
	sess = udp_proxy_find_client(shard, l, client, local, hash);
	if (sess && (!udp_proxy_srv_usable(sess->srv) || udp_proxy_srv_moved(sess))) {
		udp_proxy_delete_session(sess);
		sess = NULL;
	}

	if (!sess) {
		if (!udp_proxy_session_allowed(l))
			return NULL;

		srv = udp_proxy_select_server(l, client, local, payload, payload_len);
		if (!srv)
			return NULL;

		sess = calloc(1, sizeof(*sess));
		if (!sess)
			return NULL;

		LIST_INIT(&sess->by_hash);
		sess->listener = l;
		sess->client = *client;
		sess->local = *local;
		sess->hash = hash;
		sess->fd = -1;
		sess->srv = srv;
		if (!udp_proxy_connect_session(sess)) {
			free(sess);
			return NULL;
		}

		udp_proxy_take_server(sess);
		LIST_APPEND(&shard->buckets[hash & UDP_PROXY_HASH_MASK], &sess->by_hash);
	}

	sess->expire = tick_add(now_ms, MS_TO_TICKS(UDP_PROXY_SESS_TIMEOUT_MS));
	return sess;
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
	char *buf = udp_proxy_rxbuf;
	int max_accept;

	BUG_ON(!l);

	if (!(fdtab[fd].state & (FD_POLL_IN | FD_POLL_ERR | FD_POLL_HUP)))
		return;
	if (!fd_recv_ready(fd))
		return;
	if (unlikely(!buf))
		return;

	max_accept = l->bind_conf->maxaccept ? l->bind_conf->maxaccept : 1;
	do {
		struct sockaddr_storage from, to;
		struct udp_proxy_session *sess;
		ssize_t ret;

		ret = udp_proxy_recv(fd, l, buf, UDP_PROXY_RXBUF_SIZE, &from, &to);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				fd_cant_recv(fd);
			break;
		}

		sess = udp_proxy_get_session(l, &from, &to, buf, ret);
		if (!sess)
			continue;
		udp_proxy_send_connected(sess, buf, ret);
	} while (--max_accept);
}

/***************************************************************************
 * configuration and initialization
 ***************************************************************************/

static void udp_proxy_warn_rules(struct proxy *px, struct list *rules, const char *what)
{
	struct act_rule *rule;

	list_for_each_entry(rule, rules, list) {
		if (udp_proxy_rule_supported(rule))
			continue;
		ha_warning("parsing [%s:%d] : proxy '%s' : this '%s' rule is ignored in 'mode udp' "
		           "(only 'accept', 'reject', 'set-var', 'unset-var' and 'do-resolve' are supported).\n",
		           rule->conf.file ? rule->conf.file : "?", rule->conf.line, px->id, what);
	}
}

/* Called at the end of the configuration of every "mode udp" proxy. Reports
 * settings that UDP forwarding ignores. Returns the number of errors.
 */
int udp_proxy_check_proxy(struct proxy *px)
{
	struct switching_rule *swrule;
	struct bind_conf *bind_conf;
	struct server *srv;

	udp_proxy_used = 1;

	udp_proxy_warn_rules(px, &px->tcp_req.l4_rules, "connection");
	udp_proxy_warn_rules(px, &px->tcp_req.l5_rules, "session");
	udp_proxy_warn_rules(px, &px->tcp_req.inspect_rules, "content");

	list_for_each_entry(swrule, &px->switching_rules, list) {
		if (swrule->dynamic)
			ha_warning("parsing [%s:%d] : proxy '%s' : dynamic 'use_backend' rules are not supported in 'mode udp' and are ignored.\n",
			           swrule->file ? swrule->file : "?", swrule->line, px->id);
	}

	list_for_each_entry(bind_conf, &px->conf.bind, by_fe) {
		if (bind_conf->options & BC_O_USE_SSL)
			ha_warning("parsing [%s:%d] : proxy '%s' : 'ssl' is ignored on 'mode udp' bind '%s'.\n",
			           bind_conf->file, bind_conf->line, px->id, bind_conf->arg);
	}

	if (px->conn_src.opts & CO_SRC_TPROXY_MASK)
		ha_warning("proxy '%s' : 'source ... usesrc' is not supported in 'mode udp', only the source address is used.\n",
		           px->id);

	for (srv = px->srv; srv; srv = srv->next) {
		if (srv->use_ssl == 1)
			ha_warning("parsing [%s:%d] : proxy '%s' : 'ssl' is ignored on 'mode udp' server '%s'.\n",
			           srv->conf.file, srv->conf.line, px->id, srv->id);
		if (srv->conn_src.opts & CO_SRC_TPROXY_MASK)
			ha_warning("parsing [%s:%d] : proxy '%s' : 'source ... usesrc' is not supported on 'mode udp' server '%s', only the source address is used.\n",
			           srv->conf.file, srv->conf.line, px->id, srv->id);
		if (srv->conn_src.sport_range)
			ha_warning("parsing [%s:%d] : proxy '%s' : source port ranges are not supported on 'mode udp' server '%s'.\n",
			           srv->conf.file, srv->conf.line, px->id, srv->id);
	}

	return 0;
}

static int udp_proxy_thread_init(void)
{
	if (!udp_proxy_used)
		return 1;

	udp_proxy_rxbuf = malloc(UDP_PROXY_RXBUF_SIZE);
	if (!udp_proxy_rxbuf) {
		ha_alert("failed to allocate UDP proxy receive buffer.\n");
		return 0;
	}

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

static void udp_proxy_thread_free(void)
{
	ha_free(&udp_proxy_rxbuf);
}

REGISTER_PER_THREAD_INIT(udp_proxy_thread_init);
REGISTER_PER_THREAD_FREE(udp_proxy_thread_free);
