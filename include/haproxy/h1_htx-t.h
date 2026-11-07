/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _HAPROXY_H1_HTX_T_H
#define _HAPROXY_H1_HTX_T_H

#include <import/ist.h>
#include <import/ebpttree.h>

/* Map of headers used to convert outgoing headers */
struct h1_hdrs_map {
	char *name;
	struct eb_root map;
};

/* An entry in a headers map */
struct h1_hdr_entry  {
	struct ist name;
	struct ebpt_node node;
};

#endif /* _HAPROXY_H1_HTX_T_H */
