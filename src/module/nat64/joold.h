#ifndef _JOOL_MOD_JOOLD_H
#define _JOOL_MOD_JOOLD_H

#include "config.h"
#include "xlator.h"
#include "nat64/bib/db.h"

struct joold_queue;

/*
 * Note: "flush" in this context means "send sessions to userspace." The queue
 * is emptied as a result.
 */

/* TODO
int joold_init(void);
void joold_terminate(void);

struct joold_queue *joold_create(void);
void joold_get(struct joold_queue *queue);
void joold_put(struct joold_queue *queue);

void joold_config_copy(struct joold_queue *queue, struct joold_config *config);
void joold_config_set(struct joold_queue *queue, struct joold_config *config);

int joold_sync(struct xlator *jool, void *data, __u32 size);
void joold_add(struct xlation *state);
void joold_update_config(struct joold_queue *queue,
		struct joold_config *new_config);

int joold_test(struct xlator *jool);
int joold_advertise(struct xlator *jool);
void joold_ack(struct xlator *jool);

void joold_clean(struct joold_queue *queue, struct bib *bib);
*/

#define joold_init() 0
#define joold_terminate()

struct joold_queue *joold_create(void);
#define joold_get(queue)
#define joold_put(queue)

#define joold_sync(jool, data, size) -EINVAL
#define joold_add(state)
#define joold_update_config(queue, new_config)

#define joold_test(jool) -EINVAL
#define joold_advertise(jool) -EINVAL
#define joold_ack(jool)

#define joold_clean(queue, bib);


#endif
