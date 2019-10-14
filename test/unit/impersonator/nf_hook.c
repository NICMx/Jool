#include "mod/common/nf_wrapper.h"

NF_CALLBACK(hook_ipv6, skb)
{
	return NF_ACCEPT;
}

NF_CALLBACK(hook_ipv4, skb)
{
	return NF_ACCEPT;
}
