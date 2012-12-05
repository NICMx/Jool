#include <linux/inet.h>

#include "external_stuff.h"
#include "nf_nat64_types.h"


bool is_address_legal(struct in6_addr *address)
{
	// TODO (severe) nadie está haciendo esto.
	return true;
}

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
	pr_debug("Step 2: Filtering and Updating Binding and Session Information\n");
	pr_debug("Done step 2.\n");
	return true;
}

bool nat64_determine_outgoing_tuple_4to6(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	const char *ipv6_src = "fd68:ed5e:b31d:767d::25";
	const char *ipv6_dst = "fd68:ed5e:b31d:767d::24";
	struct nf_conntrack_tuple *result;

	pr_debug("Step 3: Computing the Outgoing Tuple\n");

	result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result) {
		pr_warning("  Can't allocate a tuple.\n");
		return false;
	}
	if (!in6_aton(ipv6_src, &result->ipv6_src_addr)) {
		pr_debug("  (4 -> 6) No puedo traducir la dirección fuente.\n");
		return false;
	}
	if (!in6_aton(ipv6_dst, &result->ipv6_dst_addr)) {
		pr_debug("  (4 -> 6) No puedo traducir la dirección destino.\n");
		return false;
	}
	pr_debug("  src: %pI6c, dst: %pI6c\n", &result->ipv6_src_addr, &result->ipv6_dst_addr);

	*tuple_out = result;
	pr_debug("Done step 3.\n");
	return true;
}

bool nat64_determine_outgoing_tuple_6to4(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out)
{
	const char *ipv4_src = "192.168.0.1";
	const char *ipv4_dst = "192.168.0.30";
	struct nf_conntrack_tuple *result;

	pr_debug("Step 3: Computing the Outgoing Tuple\n");

	result = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
	if (!result) {
		pr_warning("  Can't allocate a tuple.\n");
		return false;
	}
	result->ipv4_src_addr.s_addr = in_aton(ipv4_src);
	result->ipv4_dst_addr.s_addr = in_aton(ipv4_dst);
	pr_debug("  src: %pI4, dst: %pI4\n", &result->ipv4_src_addr, &result->ipv4_dst_addr);

	*tuple_out = result;
	pr_debug("Done step 3.\n");
	return true;
}
