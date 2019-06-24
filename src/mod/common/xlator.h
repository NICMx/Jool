#ifndef SRC_MOD_COMMON_XLATOR_H_
#define SRC_MOD_COMMON_XLATOR_H_

#include "mod/common/config.h"

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
	 *
	 * TODO (NOW) what about older kernels? What about the atomic config
	 * instances?
	 */
	struct net *ns;
	jframework fw;
	char iname[INAME_MAX_LEN];

	struct jool_stats *stats;
	/*
	 * TODO (performance) It seems like there is no point to this being a
	 * pointer anymore; global update is now implemented as an xlator
	 * instance replacement. We can avoid some dereferences.
	 */
	struct global_config *global;
	union {
		struct {
			struct eam_table *eamt;
			struct addr4_pool *blacklist4;
		} siit;
		struct {
			struct pool4 *pool4;
			struct bib *bib;
			struct joold_queue *joold;
		} nat64;
	};
};

int xlator_setup(void);
void xlator_teardown(void);

int xlator_add(jframework fw, char *iname, struct config_prefix6 *pool6,
		struct xlator *result);
int xlator_rm(char *iname);
int xlator_flush(void);

int xlator_init(struct xlator *instance,
		struct net *ns, jframework fw, char *iname,
		struct config_prefix6 *pool6);
int xlator_replace(struct xlator *instance);

int xlator_find(struct net *ns, jframework fw, const char *iname,
		struct xlator *result);
int xlator_find_current(jframework fw, const char *iname, struct xlator *result);
void xlator_put(struct xlator *instance);

typedef int (*xlator_foreach_cb)(struct xlator *, void *);
int xlator_foreach(xlator_foreach_cb cb, void *args,
		struct instance_entry_usr *offset);

#endif /* SRC_MOD_COMMON_XLATOR_H_ */
