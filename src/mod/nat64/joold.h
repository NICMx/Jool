#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "common/config.h"
#include "mod/common/xlator.h"
#include "mod/nat64/bib/entry.h"

struct joold_queue;

/*
 * Note: "flush" in this context means "send sessions to userspace." The queue
 * is emptied as a result.
 */

int joold_setup(void);
void joold_teardown(void);

struct joold_queue *joold_alloc(struct net *ns);
void joold_get(struct joold_queue *queue);
void joold_put(struct joold_queue *queue);

int joold_sync(struct xlator *jool, void *data, __u32 size);
void joold_add(struct xlator *jool, struct session_entry *entry);

int joold_test(struct xlator *jool);
int joold_advertise(struct xlator *jool);
void joold_ack(struct xlator *jool);

void joold_clean(struct xlator *jool);

#endif
