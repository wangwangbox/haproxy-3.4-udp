/*
 * include/haproxy/udp_proxy.h
 * Datagram proxying.
 */

#ifndef _HAPROXY_UDP_PROXY_H
#define _HAPROXY_UDP_PROXY_H

struct proxy;

void udp_proxy_fd_handler(int fd);
int udp_proxy_check_proxy(struct proxy *px);

#endif /* _HAPROXY_UDP_PROXY_H */
