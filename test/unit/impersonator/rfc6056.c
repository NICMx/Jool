#include "nat64/mod/stateful/pool4/rfc6056.h"

unsigned int port = 1024;

int rfc6056_init(void)
{
	return 0;
}

void rfc6056_destroy(void)
{
	/* No code. */
}

int rfc6056_f(const struct tuple *tuple6, __u8 fields, unsigned int *result)
{
	WARN(true, "This function was called! The unit test is broken.");
	return 1;
}

int palloc_allocate(struct xlation *state, struct in_addr *daddr,
		struct ipv4_transport_addr *result)
{
	result->l3.s_addr = cpu_to_be32(0xc0000280);
	result->l4 = port++;
	return 0;
}
