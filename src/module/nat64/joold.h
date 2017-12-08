#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "config.h"
#include "xlator.h"
#include "nat64/bib/entry.h"

struct joold_queue;

/*
 * Note: "flush" in this context means "send sessions to userspace." The queue
 * is emptied as a result.
 */

int joold_init(void);
void joold_terminate(void);

struct joold_queue *joold_create(struct net *ns);
void joold_get(struct joold_queue *queue);
void joold_put(struct joold_queue *queue);

void joold_config_copy(struct joold_queue *queue, struct joold_config *config);
void joold_config_set(struct joold_queue *queue, struct joold_config *config);

int joold_sync(struct xlator *jool, void *data, __u32 size);
void joold_add(struct joold_queue *queue, struct session_entry *entry,
		struct bib *bib);
void joold_update_config(struct joold_queue *queue,
		struct joold_config *new_config);

int joold_test(struct xlator *jool);
int joold_advertise(struct xlator *jool);
void joold_ack(struct xlator *jool);

void joold_clean(struct joold_queue *queue, struct bib *bib);

#endif
