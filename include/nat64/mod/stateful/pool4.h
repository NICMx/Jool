#ifndef _JOOL_MOD_NAT64_POOL4_H
#define _JOOL_MOD_NAT64_POOL4_H

/*
 * @file
 * The pool of IPv4 addresses. Stateful NAT64 Jool uses this to figure out
 * which packets should be translated.
 *
 * @author Alberto Leiva
 */

#include "nat64/common/types.h"

struct port_range {
	__u16 min;
	__u16 max;
};

struct pool4_sample {
	struct ipv4_prefix prefix;
	struct port_range range;
};

/*
 * Write functions - You *MUST* hold the configuration mutex or ensure you're
 * the only thread calling these.
 */

int pool4_init(char *prefix_strs[], int prefix_count);
void pool4_destroy(void);

int pool4_add(struct pool4_sample *sample);
int pool4_remove(struct pool4_sample *sample);
int pool4_flush(void);

/*
 * Read functions - Legal to use anywhere.
 */

bool pool4_contains_addr(__be32 addr);
bool pool4_contains_transport_addr(const struct ipv4_transport_addr *addr);
int pool4_get_nth_port(struct in_addr *addr, __u16 n, __u16 *result);

int pool4_for_each(int (*func)(struct pool4_sample *, void *), void * arg,
		struct pool4_sample *offset);
int pool4_count(__u64 *result);
bool pool4_is_empty(void);

#endif /* _JOOL_MOD_NAT64_POOL4_H */
