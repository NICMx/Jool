#ifndef SRC_MOD_NAT64_JOOLD_H_
#define SRC_MOD_NAT64_JOOLD_H_

#include "common/config.h"
#include "mod/common/db/bib/entry.h"
#include "mod/common/nl/nl_common.h"

struct joold_queue;

/*
 * Note: "flush" in this context means "send sessions to userspace." The queue
 * is emptied as a result.
 */

/* joold_setup() not needed. */
void joold_teardown(void);

struct joold_queue *joold_alloc(void);
void joold_get(struct joold_queue *queue);
void joold_put(struct joold_queue *queue);

int joold_sync(struct jnl_state *state, struct nlattr *root);
void joold_add(struct xlator *jool, struct session_entry *entry);

int joold_advertise(struct jnl_state *state);
void joold_ack(struct jnl_state *state);

void joold_clean(struct xlator *jool);

#endif /* SRC_MOD_NAT64_JOOLD_H_ */
