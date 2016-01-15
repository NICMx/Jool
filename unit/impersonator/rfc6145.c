#include "nat64/mod/common/rfc6145/6to4.h"

__u8 ttp64_xlat_tos(struct xlation *state, struct ipv6hdr *hdr)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return 0;
}

__u8 ttp64_xlat_proto(struct ipv6hdr *hdr)
{
	log_err("This function was called! The unit test is broken.");
	BUG();
	return 0;
}
