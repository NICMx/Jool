#ifndef _JOOL_MOD_NAMESPACE_H
#define _JOOL_MOD_NAMESPACE_H

#include <net/net_namespace.h>
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/pool.h"

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
			/* TODO add palloc, fragdb */
			struct taddr4_pool *pool4;
			struct bib *bib;
			struct session_db *session;
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

#endif /* _JOOL_MOD_NAMESPACE_H */
