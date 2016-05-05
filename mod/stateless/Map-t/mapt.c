#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateless/mapt/mapt.h"


static DEFINE_MUTEX(lock);
static DEFINE_MUTEX(enduser_prefix6_lock);

int mapt_init(struct mapping_rule_table **table)
{

	struct mapping_rule_table *result;
	struct mapping_rule default_rule;


	result = wkmalloc(struct mapping_rule_table, GFP_KERNEL);

	if (!result)
		return -ENOMEM;

	rtrie_init(&result->trie6, sizeof(struct mapping_rule));
	rtrie_init(&result->trie4, sizeof(struct mapping_rule));
	result->count = 0;
	kref_init(&result->refcount);

	*table = result;

	if (str_to_addr6("2001:db8:ffff::",  &default_rule.v6_prefix.address)) {
		log_err("the ipv6 address of the default mapping rule is not "
				"being parsed the right way!");
	}

	default_rule.v6_prefix.len = 64;

	memset(&default_rule.v4_prefix.address,0,sizeof(struct in_addr));
	default_rule.v4_prefix.len = 0;



	return 0;

}

int mapt_init_enduser_prefix6_table(struct enduser_prefix6_table **table)
{
	struct enduser_prefix6_table *result;
	result = wkmalloc(struct enduser_prefix6_table, GFP_KERNEL);

	if (!result)
		return -ENOMEM;

	rtrie_init(&result->trie6, sizeof(struct ipv6_prefix));
	result->count = 0;
	kref_init(&result->refcount);

	*table = result;

	return 0;
}


static int validate_prefixes(struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	int error;

	error = prefix6_validate(prefix6);
	if (error) {
		log_err("Invalid IPv6 prefix!");
		return error;
	}

	error = prefix4_validate(prefix4);
	if (error) {
		log_err("Invalid IPv4 prefix!");
		return error;
	}

	return 0;
}



static __u16 get_interface_id_psid(struct in_addr6 * map_addr6)
{

	__u8 *pointer = (__u8*)map_addr6;
	__u16 psid;

	pointer += sizeof(*map_addr6);
	pointer -= 2;

	psid =  *(__u16*)pointer;

	return psid;
}

static __u32 get_interface_id_embedded_address4(struct ind_addr6 *map_addr6)
{
	__u8 *pointer = (__u8*)map_addr6;
	__u32 ip_addr;

	pointer += sizeof(*map_addr6);
	pointer -= 6;

	ip_addr = *(__u32*)pointer;

	return ip_addr;
}


static __u64 create_ipv6_interface_identifier(struct in_addr *ipv4_prefix_or_address
		, __u16 psid)
{

	__be64 ipv6_interface_identifier = 0;
	__u8 * offset = (__u8*)ipv6_interface_identifier;

	memcpy(offset+2, ipv4_prefix_or_address, sizeof(*ipv4_prefix_or_address));
	memcpy(offset+6, &psid, sizeof(psid));


	return ipv6_interface_identifier;
}

static int create_map_ipv6_address(struct in_addr *address4,
		struct mapping_rule *rule, struct ipv6_prefix *enduser_prefix6,
		__u64 subnet_id, struct in_addr6 **result)
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


static int create_map_ipv4_address(struct ipv4_prefix *rule_ipv4_prefix,
	struct mapping_rule *rule, struct in_addr **result)
{

}


int mapt_xlat_6to4( ,struct in_addr **src_addr, struct in_addr **dst_addr)
{
	struct rtrie_key key = ADDR_TO_KEY(source6);
	struct mapping_rule rule;
	unsigned int i;
	int error;


	error = rtrie_get(&table->trie6, &key, &rule);

	if (error)
		return error;

	if (port < rule.port_range_min || port > rule.port_range_max) {
		log_err("Port outside the range allowed by the mapping rule!");
		//send // ICMPv6
		// "Destination Unreachable, source address failed ingress/egress"
		// (Type 1, Code 5)
		return -EINVAL;
	}

	// get the port set id (PSID) from the ipv6 address and check if the
	// CE is inside its allowed address and port range.

	// if the validation performed before is not successful drop the packet
	// and increment a counter to indicate the event. And respond with an
	// ICMPv6
	// "Destination Unreachable, source address failed ingress/egress"
	// (Type 1, Code 5)


	// when constructing the ipv4 packet, must derive the source and
	// destination ipv4 addresses as per section 5 of the RFC7599
	// and translate the IPv6-to-IPv4 headers as per RFC6145.
	// then pass the resulting packet for regular forwarding.
}

int mapt_xlat_4to6(struct mapping_rule_table *table, struct in_addr *source4,
		struct in_addr6 **result)
{
	// select matching rule (logest match) IPv4 + transport-layer port lookup
	// to identify the target MAP-T domain  and select the FMR and FMR rules.

	// compute and apply the IPv6 destination addresses from the IPv4
	// destination address and port as per selected FMR.

	// also compute and apply the IPv6 source addresses from the IPv4
	// source addresses  as per section 5.1 of RFC7599

	// IPv4-to-IPv6 header translation procedures outlined in RFC6145
	// apply completely

	// Pass the resulting packet for regular forwarding.

	// Note that the operation of a BR, when forwarding to/from MAP-T
	// domains that are defined without IPv4 address sharing, is the same as
	// that of stateless NAT64 IPv4/IPv6 translation.

}


static int mapt_add6(struct mapping_rule_table *table, struct mapping_rule *rule)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*rule), v6_prefix.address);
	error = rtrie_add(&table->trie6, rule, addr_offset, rule->v6_prefix.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI6c/%u already exists.",
				&rule->v6_prefix.address, rule->v6_prefix.len);
	}

	return error;
}

static int mapt_add4(struct mapping_rule_table *table, struct mapping_rule *rule)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*rule), v4_prefix.address);
	error = rtrie_add(&table->trie4, rule, addr_offset, rule->v4_prefix.len);

	if (error == -EEXIST) {
		log_err("Prefix %pI4/%u already exists.",
			&rule->v4_prefix.address, rule->v4_prefix.len);
	}

	return error;
}

int mapt_add_rule(struct mapping_rule_table *table,
		struct ipv6_prefix *enduser_prefix6,struct ipv6_prefix *v6_prefix,
		struct ipv4_prefix *v4_prefix,	__u8 embedded_address_length)
{

	int error = 0;
	struct mapping_rule new;

	error = validate_prefixes(v6_prefix, v4_prefix);

	// Validate ipv6 prefix length against ea bit field length

	if (error)
		return error;

	new.v4_prefix = *v4_prefix;
	new.v6_prefix = *v6_prefix;
	new.embedded_address_length = embedded_address_length;

	mutex_lock(&lock);

	error = mapt_add6(table, &new);

	if (error)
		goto end;

	error = mapt_add4(table, &new);

	if (error) {
		__revert_add6(table, v6_prefix);
		goto end;
	}


	end:

	mutex_unlock(&lock);
	return error;
}

static int add_enduser_prefix6(struct enduser_prefix6_table *table,
		struct ipv6_prefix *prefix6)
{
	size_t addr_offset;
	int error = 0;

	addr_offset = offsetof(typeof(*prefix6), v6_prefix.address);
	error = rtrie_add(&table->trie6, prefix6, addr_offset,
			prefix6->len);

	if (error == -EEXIST) {
		log_err("Prefix %pI6c/%u already exists.",
				prefix6->address, prefix6->len);
	}

	return error;
}

int mapt_add_enduser_prefix6(struct enduser_prefix6_table *table,
		struct ipv6_prefix *prefix6)
{

	int error = 0;

	error = prefix6_validate(prefix6);

	if (error) {
		log_err("Invalid IPv6 prefix!");
		return error;
	}

	mutex_lock(&enduser_prefix6_lock);

	error = add_enduser_prefix6(table, prefix6);

	mutex_unlock(&enduser_prefix6_lock);


	return error;
}


bool mapt_contains6(struct mapping_rule_table *table, struct in6_addr *addr)
{
	struct rtrie_key key = ADDR_TO_KEY(addr);
	return rtrie_contains(&table->trie6, &key);
}

bool mapt_contains4(struct mapping_rule_table *table, __u32 addr)
{
	struct in_addr tmp = { .s_addr = addr };
	struct rtrie_key key = ADDR_TO_KEY(&tmp);
	return rtrie_contains(&table->trie4, &key);
}

int mapt_get_matching_rule4(struct mapping_rule_table *table,
				struct ipv4_prefix *prefix)
{

}

int mapt_get_matching_rule6(struct mapping_rule_table *table,
				struct ipv6_prefix *prefix)
{

}

int mapt_count(struct mapping_rule_table *table, __u64 *count)
{
	mutex_lock(&lock);
	*count = table->count;
	mutex_unlock(&lock);
	return 0;
}

bool mapt_is_empty(struct mapping_rule_table *table)
{
	return rtrie_is_empty(&table->trie6);
}


int mapt_xlat_6to4(struct mapping_rule_table *table, struct in6_addr *addr6,
		struct in_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr6);
	struct mapping_rule rule;
	unsigned int i;
	int error;

	/* Find the entry. */
	error = rtrie_get(&table->trie6, &key, &rule);
	if (error)
		return error;


	//TODO implement this function
	return 0;
}

int mapt_xlat_4to6(struct mapping_rule_table *table, struct in_addr *addr4,
		struct in6_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr4);
	struct eamt_entry eam;
	unsigned int i;
	int error;


	//TODO implement this function
	return 0;
}

void mapt_get(struct mapping_rule_table *table)
{
	kref_get(&table->refcount);
}

void mapt_put(struct mapping_rule_table *table)
{
	kref_put(&table->refcount, destroy_mapt);
}

void mapt_enduser_get(struct enduser_prefix6_table *table)
{
	kref_get(&table->count);
}

void mapt_enduser_put(struct enduser_prefix6_table *table)
{
	kref_put(&table->count, destroy_mapt_enduser);
}

static void destroy_mapt(struct kref *refcount)
{
	struct mapping_rule_table *table;
	table = container_of(refcount, typeof(*table), refcount);
	log_debug("Emptying MAP-T table...");
	rtrie_destroy(&table->trie6);
	rtrie_destroy(&table->trie4);
	wkfree(struct mapping_rule_table, table);
}

static void destroy_mapt_enduser(struct kref *refcount)
{
	struct enduser_prefix6_table *table;
	table = container_of(refcount, typeof(*table), refcount);
	log_debug("Emptying MAP-T enduser prefix6 table...");
	rtrie_destroy(&table->trie6);
	wkfree(struct enduser_prefix6_table, table);
}

int mapt_flush(struct mapping_rule_table *table)
{
	mutex_lock(&lock);
	rtrie_flush(&table->trie6);
	rtrie_flush(&table->trie4);
	table->count = 0;
	mutex_unlock(&lock);
}


int mapt_destroy ()
{

}



 The MAP-T BR connects one or more MAP-T domains to external IPv4
networks using stateless NAT64 as extended by the MAP-T behavior
described in this document.

The MAP-T algorithmic mapping rules are identical to those in
  Section 5 of the MAP-E specification [RFC7597], with the following
  exception: the forwarding of traffic to and from IPv4 destinations
  outside a MAP-T domain is to be performed as described in this
  document, instead of Section 5.4 of the MAP-E specification.



  IPv4 traffic sent by MAP nodes that are all within one MAP domain is
     translated to IPv6, with the sender's MAP IPv6 address, derived via
     the Basic Mapping Rule (BMR), as the IPv6 source address and the
     recipient's MAP IPv6 address, derived via the Forwarding Mapping Rule
     (FMR), as the IPv6 destination address.

------------------------------------------------------------------------------

      IPv4-addressed destinations outside of the MAP domain are represented
   by means of IPv4-embedded IPv6 addresses as per [RFC6052], using the
   BR's IPv6 prefix.  For a CE sending traffic to any such destination,
   the source address of the IPv6 packet will be that of the CE's MAP
   IPv6 address, and the destination IPv6 address will be the


   destination IPv4-embedded IPv6 address.  This address mapping is said
   to be following the MAP-T Default Mapping Rule (DMR) and is defined
   in terms of the IPv6 prefix advertised by one or more BRs, which
   provide external connectivity.  A typical MAP-T CE will install an
   IPv4 default route using this rule.  A BR will use this rule when
   translating all outside IPv4 source addresses to the IPv6 MAP domain.


 -------------------------------------------------------------------------

   For a given MAP domain, the BR and CE MUST be configured with the
     following MAP parameters.  The values for these parameters are
     identical for all CEs and BRs within a given MAP-T domain.

     o  The Basic Mapping Rule and, optionally, the Forwarding Mapping
        Rules, including the Rule IPv6 prefix, Rule IPv4 prefix, and
        Length of embedded address bits

     o  Use of hub-and-spoke mode or Mesh mode (if all traffic should be
        sent to the BR, or if direct CE-to-CE correspondence should be
        supported)

     o  Use of IPv4-IPv6 translation (MAP-T)

     o  The BR's IPv6 prefix used in the DMR

 ---------------------------------------------------------------------------

 7.2.  MAP BR

    The MAP BR MUST be configured with the same MAP elements as the MAP
    CEs operating within the same domain.

    For increased reliability and load balancing, the BR IPv6 prefix MAY
    be shared across a given MAP domain.  As MAP is stateless, any BR may
    be used for forwarding to/from the domain at any time.

    Since MAP uses provider address space, no specific IPv6 or IPv4
    routes need to be advertised externally outside the service
    provider's network for MAP to operate.  However, the BR prefix needs
    to be advertised in the service provider's IGP.


