#include "nat64/mod/stateful/bib/port_allocator.h"

unsigned int port = 1024;

int palloc_init(void)
{
	return 0;
}

void palloc_destroy(void)
{
	/* No code. */
}

int palloc_allocate(struct xlation *state, struct in_addr *daddr,
		struct ipv4_transport_addr *result)
{
	result->l3.s_addr = cpu_to_be32(0xc0000280);
	result->l4 = port++;
}
