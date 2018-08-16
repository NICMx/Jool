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
	struct net *ns;
	/* One of the single-bit FW_* flags from nat64/common/config.h. */
	int fw;
	char iname[INAME_MAX_LEN];

	struct global_config *global;
	struct pool6 *pool6;
	union {
		struct {
			struct eam_table *eamt;
			struct addr4_pool *blacklist;
			struct addr4_pool *pool6791;
		} siit;
		struct {
			struct fragdb *frag;
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
int xlator_rm(int fw, char *iname);
int xlator_replace(struct xlator *instance);

int xlator_find(struct net *ns, int fw, const char *iname,
		struct xlator *result);
int xlator_find_current(int fw, const char *iname, struct xlator *result);
void xlator_put(struct xlator *instance);

typedef int (*xlator_foreach_cb)(struct xlator const *, void *);
int xlator_foreach(xlator_foreach_cb cb, void *args,
		struct instance_entry_usr *offset);

void xlator_copy_config(struct xlator *instance, struct full_config *copy);

bool xlator_matches(struct xlator *jool, struct net *ns, int fw,
		const char *iname);

#endif /* _JOOL_MOD_NAMESPACE_H */
