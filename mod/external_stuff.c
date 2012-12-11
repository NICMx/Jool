#include <linux/inet.h>

#include "external_stuff.h"
#include "nf_nat64_types.h"


bool nf_nat64_ipv4_pool_contains_addr(__be32 addr)
{
	return true;
}

bool nf_nat64_ipv6_pool_contains_addr(struct in6_addr *addr)
{
	return true;
}

bool nat64_filtering_and_updating(struct nf_conntrack_tuple *tuple_in)
{
	log_debug("Step 2: Filtering and Updating Binding and Session Information");
	log_debug("Done step 2.");
	return true;
}

bool nat64_determine_outgoing_tuple_4to6(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	const char *ipv6_src = "fd68:ed5e:b31d:767d::25";
	const char *ipv6_dst = "fd68:ed5e:b31d:767d::24";
	struct nf_conntrack_tuple *result;

	log_debug("Step 3: Computing the Outgoing Tuple");

	result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result) {
		log_warning("  Can't allocate a tuple.");
		return false;
	}

	if (!str_to_addr6(ipv6_src, &result->ipv6_src_addr)) {
		log_debug("  (4 -> 6) Can't translate the source address '%s'.", ipv6_src);
		return false;
	}
	if (!str_to_addr6(ipv6_dst, &result->ipv6_dst_addr)) {
		log_debug("  (4 -> 6) Can't translate the dest address '%s'.", ipv6_dst);
		return false;
	}
	log_debug("  src: %pI6c, dst: %pI6c", &result->ipv6_src_addr, &result->ipv6_dst_addr);

	*tuple_out = result;
	log_debug("Done step 3.");
	return true;
}

bool nat64_determine_outgoing_tuple_6to4(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	const char *ipv4_src = "192.168.0.1";
	const char *ipv4_dst = "192.168.0.30";
	struct nf_conntrack_tuple *result;

	log_debug("Step 3: Computing the Outgoing Tuple");

	result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result) {
		log_warning("  Can't allocate a tuple.");
		return false;
	}

	if (!str_to_addr4(ipv4_src, &result->ipv4_src_addr)) {
		log_warning("  (6 -> 4) Can't translate the source address '%s'.", ipv4_src);
		return false;
	}
	if (!str_to_addr4(ipv4_dst, &result->ipv4_dst_addr)) {
		log_warning("  (6 -> 4) Can't translate the dest address '%s'.", ipv4_dst);
		return false;
	}
	log_debug("  src: %pI4, dst: %pI4", &result->ipv4_src_addr, &result->ipv4_dst_addr);

	*tuple_out = result;
	log_debug("Done step 3.");
	return true;
}
