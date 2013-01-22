#ifndef _NF_NAT64_IPV6_POOL_H
#define _NF_NAT64_IPV6_POOL_H

#include "nf_nat64_types.h"
#include "nf_nat64_config.h"


bool pool6_init(void);
void pool6_destroy(void);

enum response_code pool6_register(struct ipv6_prefix *prefix);
enum response_code pool6_remove(struct ipv6_prefix *prefix);

bool pool6_contains(struct in6_addr *address);
bool pool6_peek(struct ipv6_prefix *out);
enum response_code pool6_to_array(struct ipv6_prefix **array, __u32 *size);

#endif /* _NF_NAT64_IPV6_POOL_H */
