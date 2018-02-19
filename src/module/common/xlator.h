#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include <linux/skbuff.h>
#include "config.h"

/**
 * A Jool translator "instance".
 *
 * The instance holds all the databases and configuration the translating code
 * should use to handle a packet in the respective namespace.
 */
struct xlator {
	/* Shared */
	struct jool_stats *stats;
	struct global_config *global;
	struct config_candidate *newcfg;

	/* SIIT */
	struct eam_table *eamt;

	/* NAT64 */
	struct pool4 *pool4;
	struct bib *bib;
	struct fragdb *fragdb;
	struct joold_queue *joold;
};

int xlator_add(struct xlator *result, xlator_type type, char *name);
int xlator_rm(char *name);
int xlator_replace(char *name, struct xlator *instance);
int xlator_find(char *instance, struct xlator *result);

void xlator_get(struct xlator *instance);
void xlator_put(struct xlator *instance);

typedef int (*xlator_foreach_cb)(struct xlator *, void *);
int xlator_foreach(xlator_foreach_cb cb, void *args);

void core_6to4(struct xlator *jool, struct sk_buff *skb);
void core_4to6(struct xlator *jool, struct sk_buff *skb);

#endif /* _JOOL_MOD_NAMESPACE_H */
