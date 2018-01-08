#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/pkt_queue.h"
#include "nat64/unit/unit_test.h"

static struct fake_pktqueue {
	int junk;
} dummy;

int mask_domain_next(struct mask_domain *masks,
		struct ipv4_transport_addr *addr,
		bool *consecutive)
{
	return broken_unit_call(__func__);
}

bool mask_domain_matches(struct mask_domain *masks,
		struct ipv4_transport_addr *addr)
{
	broken_unit_call(__func__);
	return false;
}

bool mask_domain_is_dynamic(struct mask_domain *masks)
{
	return false;
}

__u32 mask_domain_get_mark(struct mask_domain *masks)
{
	return 0;
}

struct pktqueue *pktqueue_create(void)
{
	return (struct pktqueue *)&dummy;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	/* No code. */
}

int pktqueue_add(struct pktqueue *queue, struct packet *pkt,
		struct ipv6_transport_addr *dst6, bool too_many)
{
	return broken_unit_call(__func__);
}

void pktqueue_rm(struct pktqueue *queue, struct ipv4_transport_addr *src4)
{
	/* No code. */
}

struct pktqueue_session *pktqueue_find(struct pktqueue *queue,
		struct ipv6_transport_addr *addr,
		struct mask_domain *masks)
{
	broken_unit_call(__func__);
	return NULL;
}

void pktqueue_put_node(struct pktqueue_session *node)
{
	broken_unit_call(__func__);
}

unsigned int pktqueue_prepare_clean(struct pktqueue *queue,
		struct list_head *probes, u64 *max_session_rm, u64 *sessions_rm,
		bool *pending_rm)
{
	return broken_unit_call(__func__);
}

void pktqueue_clean(struct list_head *probes)
{
	broken_unit_call(__func__);
}
