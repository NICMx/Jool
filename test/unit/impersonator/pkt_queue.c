#include "nat64/mod/stateful/bib/pkt_queue.h"

struct pktqueue *pktqueue_create(void)
{
	return NULL;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	/* No code. */
}

void pktqueue_config_copy(struct pktqueue *queue,
		struct pktqueue_config *config)
{
	/* No code. */
}

void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config)
{
	/* No code. */
}

int pktqueue_add(struct pktqueue *queue, struct pktqueue_session *session,
		struct packet *pkt)
{
	return 0;
}
