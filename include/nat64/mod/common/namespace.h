#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include <net/net_namespace.h>
#include "nat64/mod/common/pool6.h"

/**
 * All the configuration and state of the Jool instance in the given network
 * namespace (@ns).
 */
struct jool_instance {
	struct net *ns;

	struct global_config *global;
	struct prefix6_pool *pool6;
	union {
		struct {
			struct eam_table *eamt;
			struct blacklist_pool *blacklist;
			struct rfc6791_pool *pool6791;
		} siit;
		struct {
			struct taddr4_pool *pool4;
			struct bib *bib;
			struct session_db *session;
		} nat64;
	};

	struct kref refcount;
	/*
	 * I want to turn this into a hash table, but it doesn't seem like
	 * @ns holds anything reminiscent of an identifier...
	 */
	struct list_head list_hook;
};

int joolns_init(void);
void joolns_destroy(void);

int joolns_add(void);
int joolns_rm(void);

struct jool_instance *joolns_get(struct net *ns);
void joolns_put(struct jool_instance *meta);

#endif /* _JOOL_MOD_NAMESPACE_H */
