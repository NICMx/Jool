#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "nat64/mod/common/xlator.h"
#include "nat64/mod/stateful/session/entry.h"

struct joold_queue;

/*
 * Note: "flush" in this context means "send sessions to userspace." The queue
 * is emptied as a result.
 */

int joold_init(void);
void joold_terminate(void);

int joold_create(struct joold_queue **queue);
void joold_destroy(struct joold_queue *queue);

int joold_sync_entries(struct xlator *jool, void *data, __u32 size);
void joold_add_session(struct joold_queue *queue, struct session_entry *entry);
void joold_update_config(struct joold_queue *queue,
		struct joold_config *new_config);

#endif
