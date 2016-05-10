#include "nat64/common/mapt_ce.h"
#include "nat64/mod/stateless/mapt/mapt.h"


/**  A (NAT44) Network Address and Port Translation (NAPT) [RFC2663]
     function on a MAP CE is extended with support for restricting the
     allowable TCP/UDP ports for a given IPv4 address.  The IPv4
     address and port range used are determined by the MAP provisioning
     process and identical to MAP-E [RFC7597].*/

int mapt_ce_nat44_init(struct tcp_port_restriction_table **tcp_table,
		struct udp_port_restriction_table **udp_table)
{
	struct tcp_port_restriction_table *new_tcp;
	struct udp_port_restriction_table *new_udp;

	new_tcp = wkmalloc(struct tcp_port_restriction_table, GFP_KERNEL);

	if (!new_tcp)
		return -ENOMEM;

	new_udp = wkmalloc(struct udp_port_restriction_table, GFP_KERNEL);

	if (!new_udp)
		return -ENOMEM;

	rtrie_init(&new_tcp->trie4, sizeof(struct protocol_restricted_ports));
	new_tcp->count = 0;
	kref_init(&new_tcp->refcount);

	rtrie_init(&new_udp->trie4, sizeof(struct protocol_restricted_ports));
	new_udp->count = 0;
	kref_init(&new_udp->refcount);


	*tcp_table = new_tcp;
	*udp_table = new_udp;


	/** (this goes here) i still have to implement it
	A stateless NAT64 function [RFC6145] is extended to allow
	stateless mapping of IPv4 and transport-layer port ranges to the
	IPv6 address space. **/


	return 0;
}



static int create_map_ipv6_address(struct in_addr *address4,
		struct mapping_rule *rule, struct ipv6_prefix *enduser_prefix6,
		__u64 subnet_id, struct in_addr6 *result)
{

	__u8 mapping_rule_prefix4_length= 0;
	__u8 mapping_rule_ea_length = 0;
	__u8 ea_bitfield_suffix4_length = 0;



	if (mapping_rule_prefix4_length == 0) {

		/**  the complete ipv4 address or prefix is encoded in the EA bits  **/

	}


	if () {
		//concatenate
	}


}

static int assign_map_addr6(struct in_addr6 *map_addr, __u32 prefix_length,
			    struct xlator *jool)
{

    int error = 0;

    struct in6_ifreq req;

    req.ifr6_addr = *map_addr;
    req.ifr6_prefixlen = prefix_length;
    req.ifr6_ifindex = 0;

    error = addrconf_add_ifaddr(jool->ns, &req);

    if (error == -EPERM) {
	log_err("Not enough permissions to assing map ipv6 address!");
	return error;
    }

    if (error == -EFAULT) {
	log_err("Something is wroing in the ipv6 map address!");
	return error;
    }

    return error;
}


static int mapt_add_enduser_ipv6_prefix( struct ipv6_prefix *prefix6,
		struct xlator *jool)
{

	int error = 0;
	struct mapping_rule rule;
	struct in_addr6 map_addr6;
	struct in_addr local_addr4;

	if (enduser_prefix6_table_contains(jool->siit.mapt_enduprefix6_table,
			prefix6)) {
		return -EEXIST;
	}

	error = mapping_rule_table_get_exact_match6(jool->siit.mapt_mr_table,
			prefix6, &rule);

	if (error) {

		log_err("There is no mapping rule that matches with the "
			"enduser ipv6 prefix %pI6/%u", prefix6->address,
			prefix6->len);

		return error;
	}


	if (eup6_mr_relation_table_contains(jool->siit.relation_table, &rule))
		return -EEXIST;




	error = create_map_ipv6_address(&local_addr4, &rule, prefix6, 0,
					&map_addr6);


	if (error)
	    return error;



	error = assign_map_addr6(&map_addr6);



	return error;

	/**	when an end-user ipv6 prefix is assigned to the mapt ce this are
		the	steps to follow:

		<> Receive the End user ipv6 prefix.
		<> Find the matching mapping rule.
		<> Verify that there isn't any other End user ipv6 prefix which
		   matches against that rule.

		<> Construct the IPv6 map address and assign it to an interface
		   (check if we are going to assign it only if the interface is
		 not in use (only as primary address) or if we are going to set
		 secondary addresses too.
	*/

}


int mapt_ce_add_enduser_ipv6_prefix(struct ipv6_prefix *prefix6,
		struct enduser_prefix6_table *eu_prefix_table,
		struct map_rule_table *mr_table,
		struct eup6_mr_relation_table *relation_table)
{
  mapt_add_enduser_ipv6_prefix(prefix6, eu_prefix_table, mr_table,
		relation_table);
}




/** ---------------------------------------------------------------------- **/


   /*  Each MAP-T CE is assigned with a regular IPv6 prefix from the
     operator's IPv6 network.  This, in conjunction with MAP domain
     configuration settings and the use of the MAP procedures, allows the
     computation of a MAP IPv6 address and a corresponding IPv4 address.
     To allow for IPv4 address sharing, the CE may also have to be
     configured with a TCP/UDP port range that is identified by means of a
     MAP Port Set Identifier (PSID) value.  Each CE is responsible for
     forwarding traffic between a given user's private IPv4 address space
     and the MAP domain's IPv6 address space.  The IPv4-IPv6 adaptation
     uses stateless NAT64, in conjunction with the MAP algorithm for
     address computation. */




   /*  IPv4 traffic sent by MAP nodes that are all within one MAP domain is
        translated to IPv6, with the sender's MAP IPv6 address, derived via
        the Basic Mapping Rule (BMR), as the IPv6 source address and the
        recipient's MAP IPv6 address, derived via the Forwarding Mapping Rule
        (FMR), as the IPv6 destination address. */

	// Sender's Map IPv6 address.
	// Basic Mapping Rule
	// Forwarding Mapping Rule


//------------------------------------------------------------------------------

 /* IPv4-addressed destinations outside of the MAP domain are represented
   by means of IPv4-embedded IPv6 addresses as per [RFC6052], using the
   BR's IPv6 prefix.  For a CE sending traffic to any such destination,
   the source address of the IPv6 packet will be that of the CE's MAP
   IPv6 address, and the destination IPv6 address will be the destination
   IPv4-embedded IPv6 address.  This address mapping is said to be following
   the MAP-T Default Mapping Rule (DMR) and is defined in terms of the
   IPv6 prefix advertised by one or more BRs, which provide external
   connectivity.  A typical MAP-T CE will install an IPv4 default route
   using this rule.  A BR will use this rule when translating all outside
   IPv4 source addresses to the IPv6 MAP domain.

   The DMR IPv6 prefix length SHOULD be 64 bits long by default and in
   any case MUST NOT exceed 96 bits.  The mapping of the IPv4
   destination behind the IPv6 prefix will by default follow the /64
   rule as per [RFC6052].  Any trailing bits after the IPv4 address are
   set to 0x0. */

//------------------------------------------------------------------------------


/* For a given MAP domain, the MAP configuration parameters are the same
   across all CEs within that domain.  These values may be conveyed and
   configured on the CEs using a variety of methods, including DHCPv6,
   the Broadband Forum's "TR-69" Residential Gateway management
   interface [TR069], the Network Configuration Protocol (NETCONF), or
   manual configuration.  This document does not prescribe any of these
   methods but recommends that a MAP CE SHOULD implement DHCPv6 options
   as per [RFC7598].  Other configuration and management methods may use
   the data model described by this option for consistency and
   convenience of implementation on CEs that support multiple
   configuration methods.

   Besides the MAP configuration parameters, a CE requires an IPv6
   prefix to be assigned to the CE.  This End-user IPv6 prefix is
   configured as part of obtaining IPv6 Internet access and is acquired
   using standard IPv6 means applicable in the network where the CE is
   located.

   The MAP provisioning parameters, and hence the IPv4 service itself,
   are tied to the End-user IPv6 prefix; thus, the MAP service is also
   tied to this in terms of authorization, accounting, etc.

   A single MAP CE MAY be connected to more than one MAP domain, just as
   any router may have more than one IPv4-enabled service-provider-
   facing interface and more than one set of associated addresses
   assigned by DHCPv6.  Each domain within which a given CE operates

   would require its own set of MAP configuration elements and would
   generate its own IPv4 address.  Each MAP domain requires a distinct
   End-user IPv6 prefix. */
