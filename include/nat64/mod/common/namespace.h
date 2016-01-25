#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include <net/net_namespace.h>
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/pool.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"

/**
 * A Jool translator "instance". The point is that each network namespace has
 * a separate instance (if Jool has been loaded there).
 *
 * The instance holds all the databases and configuration that the translating
 * code should use to handle a packet.
 */
struct xlator {
	struct net *ns;

	struct global_configuration *global;
	struct pool6 *pool6;
	union {
		struct {
			struct eam_table *eamt;
			struct addr4_pool *blacklist;
			struct addr4_pool *pool6791;
		} siit;
		struct {
			/* TODO add fragdb */
			struct pool4 *pool4;
			struct bib *bib;
			struct sessiondb *session;
		} nat64;
	};
};

int joolns_init(void);
void joolns_destroy(void);

int joolns_add(void);
int joolns_rm(void);
int joolns_replace(struct xlator *jool);

int joolns_get(struct net *ns, struct xlator *result);
int joolns_get_current(struct xlator *result);
void joolns_put(struct xlator *instance);

typedef int (*joolns_foreach_cb)(struct xlator *, void *);
int joolns_foreach(joolns_foreach_cb cb, void *args);

#endif /* _JOOL_MOD_NAMESPACE_H */
