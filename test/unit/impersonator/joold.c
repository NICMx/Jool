#include "mod/nat64/joold.h"

static int trash;

struct joold_queue *joold_alloc(struct net *ns)
{
	return (struct joold_queue *)&trash;
}

void joold_get(struct joold_queue *queue)
{
	/* No code. */
}

void joold_put(struct joold_queue *queue)
{
	/* No code. */
}

void joold_add(struct xlator *jool, struct session_entry *entry)
{
	/* No code. */
}
