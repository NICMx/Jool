#include "framework/unit_test.h"
#include "mod/common/dev.h"
#include "mod/common/rfc6052.h"
#include "mod/common/db/pool4/rfc6056.h"
#include "mod/common/rfc7915/6to4.h"

int rfc6056_f(struct xlation *state, unsigned int *result)
{
	return broken_unit_call(__func__);
}

int __rfc6052_4to6(struct ipv6_prefix const *prefix, struct in_addr const *src,
		struct in6_addr *dst)
{
	return broken_unit_call(__func__);
}

int __rfc6052_6to4(struct ipv6_prefix const *prefix, struct in6_addr const *src,
		struct in_addr *dst)
{
	return broken_unit_call(__func__);
}

verdict predict_route64(struct xlation *state)
{
	broken_unit_call(__func__);
	return VERDICT_DROP;
}

int foreach_ifa(struct net *ns, int (*cb)(struct in_ifaddr *, void const *),
		void const *args)
{
	return broken_unit_call(__func__);
}
