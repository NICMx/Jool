#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/pkt_queue.h"
#include "nat64/unit/unit_test.h"

struct fake_pktqueue {
	int junk;
} dummy;

int mask_domain_next(struct mask_domain *masks,
		struct ipv4_transport_addr *addr,
		bool *consecutive)
{
	return broken_unit_call(__func__);
}

struct pktqueue *pktqueue_create(void)
{
	return (struct pktqueue *)&dummy;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	/* No code. */
}

void pktqueue_config_copy(struct pktqueue *queue,
		struct pktqueue_config *config)
{
	broken_unit_call(__func__);
}

void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config)
{
	broken_unit_call(__func__);
}

int pktqueue_add(struct pktqueue *queue, struct pktqueue_session *session,
		struct packet *pkt)
{
	return broken_unit_call(__func__);
}
