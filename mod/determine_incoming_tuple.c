#include "nat64/mod/determine_incoming_tuple.h"
#include "nat64/comm/types.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack_l3proto.h>


/**
 * log_tuple() - Prints the "tuple" tuple on the kernel ring buffer.
 * @tuple:	Structure to be dumped on logging.
 *
 * It's a ripoff of nf_ct_dump_tuple(), adjusted to comply to this project's logging requirements.
 */
static inline void log_tuple(const struct nf_conntrack_tuple *tuple)
{
	switch (tuple->src.l3num) {
	case PF_INET:
		log_debug("tuple %p: l3:%u l4:%u %pI4#%hu -> %pI4#%hu",
				tuple, tuple->src.l3num, tuple->dst.protonum,
				&tuple->src.u3.ip, ntohs(tuple->src.u.all),
				&tuple->dst.u3.ip, ntohs(tuple->dst.u.all));
		break;
	case PF_INET6:
		log_debug("tuple %p: l3:%u l4:%u %pI6c#%hu -> %pI6c#%hu",
				tuple, tuple->src.l3num, tuple->dst.protonum,
				&tuple->src.u3.all, ntohs(tuple->src.u.all),
				&tuple->dst.u3.all, ntohs(tuple->dst.u.all));
		break;
	}
}

/**
 * is_l4_protocol_supported_ipv4() - Returns whether the NAT64 can handle packets using the
 * "l4protocol" transport protocol when the network protocol is IPv4.
 * @l4protocol:	transport protocol id to test.
 */
static inline bool is_l4_protocol_supported_ipv4(u_int8_t l4protocol)
{
	return l4protocol == IPPROTO_TCP
			|| l4protocol == IPPROTO_UDP
			|| l4protocol == IPPROTO_ICMP;
}

/**
 * is_l4_protocol_supported_ipv6() - Returns whether the NAT64 can handle packets using the
 * "l4protocol" transport protocol when the network protocol is IPv6.
 * @l4protocol transport protocol id to test.
 */
static inline bool is_l4_protocol_supported_ipv6(u_int8_t l4protocol)
{
	return l4protocol == IPPROTO_TCP
			|| l4protocol == IPPROTO_UDP
			|| l4protocol == IPPROTO_ICMPV6;
}

bool determine_in_tuple(struct sk_buff *skb, struct nf_conntrack_tuple *tuple)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;

	log_debug("Step 1: Determining the Incoming Tuple");

	/** Conntrack already built the tuple, so just ask. */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct) {
		log_err(ERR_CONNTRACK, "Packet does not contain a conntrack entry. Dropping...");
		return false;
	}
	dir = CTINFO2DIR(ctinfo);
	*tuple = ct->tuplehash[dir].tuple;

	if ( tuple->L4_PROTO == IPPROTO_ICMPV6 || tuple->L4_PROTO == IPPROTO_ICMP )
		tuple->dst_port = tuple->src_port;

	log_tuple(tuple);

	/** Now perform the only validation defined in this step. */
	switch (tuple->L3_PROTO) {
	case PF_INET:
		if (!is_l4_protocol_supported_ipv4(tuple->L4_PROTO)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);
			goto unsupported_l4_protocol;
		}
		break;
	case PF_INET6:
		if (!is_l4_protocol_supported_ipv6(tuple->L4_PROTO)) {
			icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
			goto unsupported_l4_protocol;
		}
		break;
	default:
		goto unsupported_l3_protocol;
	}

	log_debug("Done step 1.");
	return true;

unsupported_l3_protocol:
	log_err(ERR_L3PROTO, "Unsupported network protocol: %u.", tuple->L3_PROTO);
	return false;

unsupported_l4_protocol:
	log_err(ERR_L4PROTO, "Unsupported transport protocol: %u.", tuple->L4_PROTO);
	return false;
}
