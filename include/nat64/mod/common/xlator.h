#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include "nat64/mod/common/config.h"

/**
 * A Jool translator "instance". The point is that each network namespace has
 * a separate instance (if Jool has been loaded there).
 *
 * The instance holds all the databases and configuration the translating code
 * should use to handle a packet in the respective namespace.
 */
struct xlator {
	/*
	 * Note: This xlator must not increase @ns's kref counter.
	 * Quite the opposite: The @ns has to reference count the xlator.
	 * (The kernel does this somewhere in the register_pernet_subsys() API.)
	 * Otherwise the Jool instance would prevent the namespace from dying,
	 * and in turn the namespace would prevent the Jool instance from dying.
	 *
	 * As a matter of fact, I'll say it here because there's no better place
	 * for it: whenever Jool acquires a reference to a namespace, it should
	 * *ALWAYS* return it, preferably during the same function.
	 */
	struct net *ns;
	/* One of the single-bit FW_* flags from nat64/common/config.h. */
	int fw;
	char iname[INAME_MAX_LEN];

	struct jool_stats *stats;
	struct global_config *global;
	struct pool6 *pool6;
	union {
		struct {
			struct eam_table *eamt;
			struct addr4_pool *blacklist;
			struct addr4_pool *pool6791;
		} siit;
		struct {
			struct pool4 *pool4;
			struct bib *bib;
			struct joold_queue *joold;
		} nat64;
	};

	struct config_candidate *newcfg;
};

int xlator_setup(void);
void xlator_teardown(void);

int xlator_add(int fw, char *iname, struct xlator *result);
int xlator_rm(char *iname);
int xlator_replace(struct xlator *instance);
int xlator_flush(void);

int xlator_find(struct net *ns, int fw, const char *iname,
		struct xlator *result);
int xlator_find_current(int fw, const char *iname, struct xlator *result);
void xlator_put(struct xlator *instance);

typedef int (*xlator_foreach_cb)(struct xlator const *, void *);
int xlator_foreach(xlator_foreach_cb cb, void *args,
		struct instance_entry_usr *offset);

void xlator_copy_config(struct xlator *instance, struct full_config *copy);

#endif /* _JOOL_MOD_NAMESPACE_H */
