#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/icmp.h>

#include "nf_nat64_translate_packet.h"

/** TODO currently unused. We don't know what's supposed to represent either. */
#define ICMP_MINLEN						8
/** ICMP Type missing in icmp.h. */
#define ICMP_ROUTER_ADVERTISEMENT		9
/** ICMP Type missing in icmp.h. */
#define ICMP_ROUTER_SOLICITATION		10
/** Evaluates to true if "type" is a known non-error ICMP type code. */
#define ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
	 (type) == ICMP_ROUTER_ADVERTISEMENT || (type) == ICMP_ROUTER_SOLICITATION || \
	 (type) == ICMP_TIMESTAMP || (type) == ICMP_TIMESTAMPREPLY || \
	 (type) == ICMP_INFO_REQUEST || (type) == ICMP_INFO_REPLY || \
	 (type) == ICMP_ADDRESS || (type) == ICMP_ADDRESSREPLY)

/*
 * BEGIN SUBSECTION: ECDYSIS FUNCTIONS
 */

static inline void nat64_checksum_adjust(uint16_t *sum, uint16_t old, uint16_t new,
        bool udp) {
	uint32_t s;

	if (udp && !*sum)
		return;

	s = *sum + old - new;
	*sum = (s & 0xffff) + (s >> 16);

	if (udp && !*sum)
		*sum = 0xffff;
}

static inline void nat64_checksum_remove(uint16_t *sum, uint16_t *begin,
        uint16_t *end, bool udp) {
	while (begin < end)
		nat64_checksum_adjust(sum, *begin++, 0, udp);
}

static inline void nat64_checksum_add(uint16_t *sum, uint16_t *begin, uint16_t *end,
        bool udp) {
	while (begin < end)
		nat64_checksum_adjust(sum, 0, *begin++, udp);
}

static inline void nat64_checksum_change(uint16_t *sum, uint16_t *x, uint16_t new,
        bool udp) {
	nat64_checksum_adjust(sum, *x, new, udp);
	*x = new;
}

static inline void nat64_adjust_checksum_ipv6_to_ipv4(uint16_t *sum,
        struct ipv6hdr *ip6, struct iphdr *ip4, bool udp) {
	WARN_ON_ONCE(udp && !*sum);

	nat64_checksum_remove(sum, (uint16_t *) &ip6->saddr, (uint16_t *) (&ip6->saddr
	        + 2), udp);

	nat64_checksum_add(sum, (uint16_t *) &ip4->saddr, (uint16_t *) (&ip4->saddr + 2),
	        udp);
}

static inline void nat64_adjust_checksum_ipv4_to_ipv6(uint16_t *sum,
        struct iphdr *ip4, struct ipv6hdr *ip6, int udp) {
	WARN_ON_ONCE(udp && !*sum);

	nat64_checksum_remove(sum, (uint16_t *) &ip4->saddr, (uint16_t *) (&ip4->saddr
	        + 2), udp);

	nat64_checksum_add(sum, (uint16_t *) &ip6->saddr, (uint16_t *) (&ip6->saddr + 2),
	        udp);
}

/*
 * END SUBSECTION: ECDYSIS FUNCTIONS
 */

/*
 * Returns a pointer to the Layer 4 header, contained within the "ip4" packet.
 */
static inline void * nat64_ip_data(struct iphdr *ip4) {
	return (char *) ip4 + ip4->ihl * 4;
}

static bool nat64_get_skb_from6to6(struct sk_buff * old_skb,
        struct sk_buff * new_skb, u_int8_t l3protocol, u_int8_t l4protocol,
        int l3len, int l4len, int pay_len, struct nf_conntrack_tuple * outgoing) {
	union nat64_l4header_t {
		struct udphdr * uh;
		struct tcphdr * th;
	} l4header;

	struct ipv6hdr * ip6;
	struct ipv6hdr * ip6_old;
	void * ip6_transp;

	ip6 = ipv6_hdr(new_skb);
	ip6_old = ipv6_hdr(old_skb);

	ip6->version = ip6_old->version;
	ip6->priority = ip6_old->priority;
	ip6->flow_lbl[0] = ip6_old->flow_lbl[0];
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;

	ip6->payload_len = htons(pay_len);
	ip6->nexthdr = ip6_old->nexthdr;
	ip6->hop_limit = ip6_old->hop_limit;

	ipv6_addr_copy(&ip6->saddr, &outgoing->src.u3.in6);
	ipv6_addr_copy(&ip6->daddr, &outgoing->dst.u3.in6);

	/*
	 * Get pointer to Layer 4 header.
	 */
	ip6_transp = skb_transport_header(old_skb);

	switch (ip6->nexthdr) {
		case IPPROTO_UDP:
			l4header.uh = (struct udphdr *) (ip6 + 1);
			memcpy(l4header.uh, ip6_transp, l4len + pay_len);
			//checksum_change(&l4header.uh->check,&l4header.uh->dest,outgoing->dst.u.udp.port, true);
			l4header.uh->dest = outgoing->dst.u.udp.port;
			l4header.uh->source = outgoing->src.u.udp.port;
			l4header.uh->check = 0;
			l4header.uh->check = csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
			        l4len + pay_len, IPPROTO_UDP, csum_partial(l4header.uh,
			                l4len + pay_len, 0));
			pr_debug("checksum hairpin,%d ", l4header.uh->check);
			break;
		case IPPROTO_TCP:
			l4header.th = (struct tcphdr *) (ip6 + 1);
			memcpy(l4header.th, ip6_transp, l4len + pay_len);
			//checksum_change(&l4header.th->check,&l4header.th->dest,outgoing->dst.u.tcp.port, false);
			l4header.th->dest = outgoing->dst.u.tcp.port;
			l4header.th->source = outgoing->src.u.tcp.port;
			l4header.th->check = 0;
			l4header.th->check = csum_ipv6_magic(&ip6->saddr, &ip6->daddr,
			        l4len + pay_len, IPPROTO_TCP, csum_partial(l4header.th,
			                l4len + pay_len, 0));
			pr_debug("checksum hairpin,%d ", l4header.th->check);
			break;

		default:
			WARN_ON_ONCE(1);
			return false;
	}

	return true;
}

/*
 * Function to get the SKB from IPv6 to IPv4.
 * @l4protocol = The incoming L4 protocol
 * @l3len = The outgoing L3 header length
 * @l4len = The outgoing l4 header length
 * @paylen = transport header length + data length
 *
 * IMPORTANT: We don't take into account the optional IPv6 header yet.
 */
static bool nat64_get_skb_from6to4(struct sk_buff * old_skb,
        struct sk_buff * new_skb, u_int8_t l3protocol, u_int8_t l4protocol,
        int l3len, int l4len, int pay_len, struct nf_conntrack_tuple * outgoing) {
	/*
	 * Genric Layer 4 header structure.
	 */
	union nat64_l4header_t {
		struct udphdr * uh;
		struct tcphdr * th;
		struct icmphdr * icmph;
		struct icmp6hdr * icmph6;
	} l4header;

	struct ipv6hdr * ip6;
	struct iphdr * ip4;
	void * ip6_transp;

	struct ipv6_opt_hdr *ip6e;

	ip6 = ipv6_hdr(old_skb);
	ip4 = ip_hdr(new_skb);

	/*
	 * IPv4 construction.
	 */
	ip4->version = 4;
	ip4->ihl = 5;
	ip4->tos = ip6->priority;
	ip4->tot_len = htons(new_skb->len);

	/*
	 * According to the RFC6146 the ID should be zero.
	 */
	ip4->id = 0;
	ip4->frag_off = pay_len > 1280 ? htons(IP_DF) : 0;
	ip4->ttl = ip6->hop_limit;
	ip4->protocol = ip6->nexthdr;

	pr_debug("NAT64: l4 proto id = %u", ip6->nexthdr);

	ip4->saddr = outgoing->src.u3.in.s_addr;
	ip4->daddr = outgoing->dst.u3.in.s_addr;

	/*
	 * Get pointer to Layer 4 header.
	 * FIXME: IPv6 option headers should also be considered.
	 */
	ip6_transp = skb_transport_header(old_skb);

	/* Skip extension headers. */
	ip6e = (struct ipv6_opt_hdr *) (ip6 + 1);
	while (ip4->protocol == 0 || ip4->protocol == 43 || ip4->protocol == 60) {
		ip4->protocol = ip6e->nexthdr;
		ip6e = (struct ipv6_opt_hdr *) ((char *) ip6e + ip6e->hdrlen * 8);
	}

	switch (ip4->protocol) {
		/*
		 * UDP and TCP have the same two first values in the struct.
		 * So UDP header values are used in order to save code.
		 */
		case IPPROTO_UDP:
			l4header.uh = nat64_ip_data(ip4);
			memcpy(l4header.uh, ip6_transp, l4len + pay_len);

			pr_debug(
			        "NAT64: DEBUG: (outgoing->src.u.udp.port = %d), (outgoing->dst.u.udp.port = %d)",
			        ntohs(outgoing->src.u.udp.port), ntohs(
			                outgoing->dst.u.udp.port));
			nat64_checksum_change(&(l4header.uh->check), &(l4header.uh->source),
			//&(l4header.uh->dest),
			        (outgoing->src.u.udp.port),
			        //(outgoing->dst.u.udp.port),
			        (ip4->protocol == IPPROTO_UDP) ? true : false);

			nat64_adjust_checksum_ipv6_to_ipv4(&(l4header.uh->check), ip6, ip4,
			        (ip4->protocol == IPPROTO_UDP) ? true : false);
			break;
		case IPPROTO_TCP:
			l4header.th = nat64_ip_data(ip4);
			memcpy(l4header.th, ip6_transp, l4len + pay_len);

			nat64_checksum_change(&(l4header.th->check), &(l4header.th->source),
			        outgoing->src.u.tcp.port, false);

			nat64_adjust_checksum_ipv6_to_ipv4(&(l4header.th->check), ip6, ip4, false);
			break;
		case IPPROTO_ICMPV6:
			l4header.icmph = nat64_ip_data(ip4);
			memcpy(l4header.icmph, ip6e, l4len + pay_len);

			if (l4header.icmph->type & ICMPV6_INFOMSG_MASK) {
				switch (l4header.icmph->type) {
					case ICMPV6_ECHO_REQUEST:
						pr_debug("NAT64: icmp6 type"
							" ECHO_REQUEST");
						l4header.icmph->type = ICMP_ECHO;
						break;
					case ICMPV6_ECHO_REPLY:
						pr_debug("NAT64: icmp6 type"
							" ECHO_REPLY");
						l4header.icmph->type = ICMP_ECHOREPLY;
						break;
					default:
						pr_debug("NAT64: ICMPv6 not "
							"echo or reply");
						return false;
				}
			} else {
				switch (l4header.icmph->type) {
					case ICMPV6_DEST_UNREACH:
						l4header.icmph->type = ICMP_DEST_UNREACH;
						switch (l4header.icmph->code) {
							case ICMPV6_NOROUTE:
							case ICMPV6_NOT_NEIGHBOUR:
							case ICMPV6_ADDR_UNREACH:
								l4header.icmph->code = ICMP_HOST_UNREACH;
								break;
							case ICMPV6_ADM_PROHIBITED:
								l4header.icmph->code = ICMP_HOST_ANO;
								break;
							case ICMPV6_PORT_UNREACH:
								l4header.icmph->code = ICMP_PORT_UNREACH;
								break;
							default:
								return NULL;
						}
						break;
					case ICMPV6_PKT_TOOBIG:
						l4header.icmph6 = (struct icmp6hdr *) (ip6 + 1);
						l4header.icmph->type = ICMP_DEST_UNREACH;
						l4header.icmph->code = ICMP_FRAG_NEEDED;
						if (ntohl(l4header.icmph6->icmp6_mtu) >= 0xffff) {
							l4header.icmph->un.frag.mtu = 0xffff; //same in host and network order
						} else {
							// IPv4 has 2 bytes, IPv6 has 4 bytes.
							l4header.icmph->un.frag.mtu = htons(ntohl(
							        l4header.icmph6->icmp6_mtu) - 20);
						}
						break;
					case ICMPV6_TIME_EXCEED:
						l4header.icmph->type = ICMP_TIME_EXCEEDED;
						break;
					case ICMPV6_PARAMPROB:
						if (l4header.icmph->code == ICMPV6_UNK_NEXTHDR) {
							l4header.icmph->type = ICMP_DEST_UNREACH;
							l4header.icmph->code = ICMP_PROT_UNREACH;
						} else {
							l4header.icmph->type = ICMP_PARAMETERPROB;
							l4header.icmph->code = 0;
						}
						/* TODO update pointer */
						break;
					default:
						return NULL;
				}
				/*nat64_xlate_ipv6_to_ipv4(*/
				/*(struct ipv6hdr *)((char *)ip6e + 8),*/
				/*(struct iphdr *)(l4header.icmph + 1), */
				/*plen - ((char *)ip6e + 8 - (char *)ip6), s,*/
				/*recur + 1);*/

			}

			l4header.icmph->checksum = 0;
			l4header.icmph->checksum = ip_compute_csum(l4header.icmph, l4len
			        + pay_len);
			ip4->protocol = IPPROTO_ICMP;
			break;
		default:
			pr_debug("NAT64: encountered incompatible protocol "
				"while creating the outgoing skb");
			return false;
	}

	ip4->check = 0;
	ip4->check = ip_fast_csum(ip4, ip4->ihl);

	return true;
}

/*
 * Function to get the SKB from IPv4 to IPv6.
 * @l4protocol = The incoming L4 protocol
 * @l3len = The outgoing L3 header length
 * @l4len = The outgoing l4 header length
 * @paylen = transport header length + data length
 *
 * IMPORTANT: We don't take into account the optional IPv6 header yet.
 */
static bool nat64_get_skb_from4to6(struct sk_buff * old_skb,
        struct sk_buff * new_skb, u_int8_t l3protocol, u_int8_t l4protocol,
        int l3len, int l4len, int pay_len, struct nf_conntrack_tuple * outgoing) {
	union nat64_l4header_t {
		struct udphdr * uh;
		struct tcphdr * th;
		struct icmp6hdr * icmph;
	} l4header;

	struct ipv6hdr * ip6;
	struct iphdr * ip4;
	void * ip_transp;

	ip6 = ipv6_hdr(new_skb);
	ip4 = ip_hdr(old_skb);

	ip6->version = 6;
	ip6->priority = 0;
	ip6->flow_lbl[0] = 0;
	ip6->flow_lbl[1] = 0;
	ip6->flow_lbl[2] = 0;

	ip6->payload_len = htons(pay_len);
	ip6->nexthdr = ip4->protocol;
	ip6->hop_limit = ip4->ttl;

	memcpy(&(ip6->saddr), &(outgoing->src.u3.in6), sizeof(struct in6_addr)); // Y'
	memcpy(&(ip6->daddr), &(outgoing->dst.u3.in6), sizeof(struct in6_addr)); // X'

	/*
	 * Get pointer to Layer 4 header.
	 */
	ip_transp = skb_transport_header(old_skb);

	switch (ip6->nexthdr) {
		case IPPROTO_UDP:
			l4header.uh = (struct udphdr *) (ip6 + 1);
			memcpy(l4header.uh, nat64_ip_data(ip4), l4len + pay_len);
			nat64_checksum_change(&(l4header.uh->check),
			//&(l4header.uh->source),
			        &(l4header.uh->dest),
			        //outgoing->src.u.udp.port, // Rob.
			        outgoing->dst.u.udp.port, // Rob.
			        (ip4->protocol == IPPROTO_UDP) ? true : false);
			nat64_adjust_checksum_ipv4_to_ipv6(&(l4header.uh->check), ip4, ip6,
			        (ip4->protocol == IPPROTO_UDP) ? true : false);

			break;
		case IPPROTO_TCP:
			l4header.th = (struct tcphdr *) (ip6 + 1);
			memcpy(l4header.th, nat64_ip_data(ip4), l4len + pay_len);
			nat64_checksum_change(&(l4header.th->check),
			//&(l4header.th->source),
			        &(l4header.th->dest),
			        //htons(outgoing->src.u.tcp.port),
			        //outgoing->src.u.tcp.port, // Rob.
			        outgoing->dst.u.tcp.port, // Rob.
			        false);
			nat64_adjust_checksum_ipv4_to_ipv6(&(l4header.th->check), ip4, ip6, false);
			break;
		case IPPROTO_ICMP:
			l4header.icmph = (struct icmp6hdr *) (ip6 + 1);
			memcpy(l4header.icmph, nat64_ip_data(ip4), l4len + pay_len);
			if (ICMP_INFOTYPE(l4header.icmph->icmp6_type)) {
				switch (l4header.icmph->icmp6_type) {
					case ICMP_ECHO:
						l4header.icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
						break;
					case ICMP_ECHOREPLY:
						l4header.icmph->icmp6_type = ICMPV6_ECHO_REPLY;
						break;
					default:
						return NULL;
				}
			} else {
				switch (l4header.icmph->icmp6_type) {
					case ICMP_DEST_UNREACH:
						l4header.icmph->icmp6_type = ICMPV6_DEST_UNREACH;
						switch (l4header.icmph->icmp6_code) {
							case ICMP_NET_UNREACH:
							case ICMP_HOST_UNREACH:
								l4header.icmph->icmp6_code = ICMPV6_NOROUTE;
								break;
							case ICMP_PORT_UNREACH:
								l4header.icmph->icmp6_code
								        = ICMPV6_PORT_UNREACH;
								break;
							case ICMP_SR_FAILED:
							case ICMP_NET_UNKNOWN:
							case ICMP_HOST_UNKNOWN:
							case ICMP_HOST_ISOLATED:
							case ICMP_NET_UNR_TOS:
							case ICMP_HOST_UNR_TOS:
								l4header.icmph->icmp6_code = ICMPV6_NOROUTE;
								break;
							case ICMP_NET_ANO:
							case ICMP_HOST_ANO:
								l4header.icmph->icmp6_code
								        = ICMPV6_ADM_PROHIBITED;
								break;
							case ICMP_PROT_UNREACH:
								l4header.icmph->icmp6_type = ICMPV6_PARAMPROB;
								l4header.icmph->icmp6_code = ICMPV6_UNK_NEXTHDR;
								l4header.icmph->icmp6_pointer
								        = (char *) &ip6->nexthdr - (char *) ip6;
								break;
							case ICMP_FRAG_NEEDED:
								l4header.icmph->icmp6_type = ICMPV6_PKT_TOOBIG;
								l4header.icmph->icmp6_code = 0;
								l4header.icmph->icmp6_mtu = htonl(ntohs(
								        l4header.icmph->icmp6_mtu) + 20);
								/* TODO handle icmp_nextmtu == 0 */
								break;
							default:
								return NULL;
						}
						break;
					case ICMP_TIME_EXCEEDED:
						l4header.icmph->icmp6_type = ICMPV6_TIME_EXCEED;
						break;
					case ICMP_PARAMETERPROB:
						l4header.icmph->icmp6_type = ICMPV6_PARAMPROB;
						/* TODO update pointer */
						break;
					default:
						return NULL;
				}
			}
			l4header.icmph->icmp6_cksum = 0;
			ip6->nexthdr = IPPROTO_ICMPV6;
			l4header.icmph->icmp6_cksum = csum_ipv6_magic(&ip6->saddr,
			        &ip6->daddr, l4len + pay_len, IPPROTO_ICMPV6, csum_partial(
			                l4header.icmph, l4len + pay_len, 0));
			break;
		default:
			WARN_ON_ONCE(1);
			return false;
	}

	return true;
}

/*
 * Function that gets the Layer 4 header length.
 */
static inline int nat64_get_l4hdrlength(u_int8_t l4protocol) {
	switch (l4protocol) {
		case IPPROTO_TCP:
			return sizeof(struct tcphdr);
		case IPPROTO_UDP:
			return sizeof(struct udphdr);
		case IPPROTO_ICMP:
			return sizeof(struct icmphdr);
		case IPPROTO_ICMPV6:
			return sizeof(struct icmp6hdr);
	}
	return -1;
}

/*
 * Function nat64_get_skb is a generic entry function to get a new skb 
 * that will be sent.
 */
static struct sk_buff * nat64_get_skb(u_int8_t l3protocol, u_int8_t l4protocol,
        struct sk_buff *skb, struct nf_conntrack_tuple * outgoing, bool hairpin) {
	struct sk_buff *new_skb;

	int pay_len = skb->len - skb->data_len;
	int packet_len, l4hdrlen, l3hdrlen, l2hdrlen;

	l4hdrlen = -1;

	/*
	 * Layer 2 header length is assigned the maximum possible header length
	 * possible.
	 */
	l2hdrlen = LL_MAX_HEADER;

	pr_debug("NAT64: get_skb paylen = %u", pay_len);

	/*
	 * This is called in case a paged sk_buff arrives...this should'nt
	 * happen.
	 */
	if (skb_linearize(skb) < 0)
		return NULL;

	/*
	 * It's assumed that if the l4 protocol is ICMP or ICMPv6,
	 * the size of the new header will be the other's.
	 */
	switch (l4protocol) {
		case IPPROTO_ICMP:
			l4hdrlen = sizeof(struct icmp6hdr);
			pay_len = pay_len - sizeof(struct icmphdr);
			break;
		case IPPROTO_ICMPV6:
			l4hdrlen = sizeof(struct icmphdr);
			pay_len = pay_len - sizeof(struct icmp6hdr);
			break;
		default:
			l4hdrlen = nat64_get_l4hdrlength(l4protocol);
			pay_len = pay_len - nat64_get_l4hdrlength(l4protocol);
	}

	/*
	 * We want to get the opposite Layer 3 protocol header length.
	 */
	switch (l3protocol) {
		case NFPROTO_IPV4:
			l3hdrlen = sizeof(struct ipv6hdr);
			pay_len = pay_len - sizeof(struct iphdr);
			break;
		case NFPROTO_IPV6:
			if (hairpin) {
				l3hdrlen = sizeof(struct ipv6hdr);
				pay_len = pay_len - sizeof(struct ipv6hdr);
			} else {
				l3hdrlen = sizeof(struct iphdr);
				pay_len = pay_len - sizeof(struct ipv6hdr);
			}
			break;
		default:
			pr_debug("NAT64: nat64_get_skb - unidentified"
				" layer 3 protocol");
			return NULL;
	}
	pr_debug("NAT64: paylen %d", pay_len);
	pr_debug("NAT64: l3hdrlen %d", l3hdrlen);
	pr_debug("NAT64: l4hdrlen %d", l4hdrlen);

	packet_len = l3hdrlen + l4hdrlen + pay_len;
	pr_debug("NAT64: packet len %d", packet_len);

	pr_debug("NAT64: packet len %d", packet_len);

	/*
	 * LL_MAX_HEADER referes to the 'link layer' in the OSI stack.
	 */
	new_skb = alloc_skb(l2hdrlen + packet_len, GFP_ATOMIC);

	if (!new_skb) {
		pr_debug("NAT64: Couldn't allocate space for new skb");
		return NULL;
	}

	/*
	 * At this point skb->data and skb->head are at the same place.
	 * They will be separated by the skb_reserve function.
	 */
	skb_reserve(new_skb, l2hdrlen);
	skb_reset_mac_header(new_skb);

	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, l3hdrlen);

	/*
	 * The skb->data pointer is right on the l2 header.
	 * We move skb->tail to the end of the packet data.
	 */
	skb_put(new_skb, packet_len);

	if (!new_skb) {
		if (printk_ratelimit()) {
			pr_debug("NAT64: failed to alloc a new sk_buff");
		}
		return NULL;
	}

	switch (l3protocol) {
		case NFPROTO_IPV4:
			if (nat64_get_skb_from4to6(skb, new_skb, l3protocol, l4protocol,
			        l3hdrlen, l4hdrlen, (pay_len), outgoing)) {
				pr_debug("NAT64: Everything went OK populating the "
					"new sk_buff");
				return new_skb;
			}

			pr_debug("NAT64: something went wrong populating the "
				"new sk_buff");
			return NULL;
		case NFPROTO_IPV6:
			if (hairpin) {

				if (nat64_get_skb_from6to6(skb, new_skb, l3protocol,
				        l4protocol, l3hdrlen, l4hdrlen, (pay_len), outgoing)) {
					pr_debug(
					        "NAT64 hairpin: Everything went OK populating the "
						        "new sk_buff");
					return new_skb;
				}

				pr_debug("NAT64: something went wrong populating the "
					"new sk_buff");
				return NULL;

			} else {

				if (nat64_get_skb_from6to4(skb, new_skb, l3protocol,
				        l4protocol, l3hdrlen, l4hdrlen, (pay_len), outgoing)) {
					pr_debug("NAT64: Everything went OK populating the "
						"new sk_buff");
					return new_skb;
				}

				pr_debug("NAT64: something went wrong populating the "
					"new sk_buff");
				return NULL;
			}
	}

	pr_debug("NAT64: Not IPv4 or 6");
	return NULL;
}

struct sk_buff * nat64_translate_packet(u_int8_t l3protocol,
        u_int8_t l4protocol, struct sk_buff *skb,
        struct nf_conntrack_tuple * outgoing, bool hairpin) {
	/*
	 * FIXME: Handle IPv6 options.
	 * The following changes the skb and the L3 and L4 layer protocols to
	 * the respective new values and calls determine_outgoing_tuple.
	 */
	struct sk_buff * new_skb = nat64_get_skb(l3protocol, l4protocol, skb,
	        outgoing, hairpin);

	if (!new_skb) {
		pr_debug("NAT64: Skb allocation failed -- returned NULL");
		return NULL;
	}

	/*
	 * Adjust the layer 3 protocol variable to be used in the outgoing tuple
	 * Wether it's IPV4 or IPV6 is already checked in the nat64_tg function
	 */
	if (!hairpin)
		l3protocol = (l3protocol == NFPROTO_IPV4) ? NFPROTO_IPV6 : NFPROTO_IPV4;

	/*
	 * Adjust the layer 4 protocol variable to be used
	 * in the outgoing tuple.
	 */
	if (l4protocol == IPPROTO_ICMP) {
		l4protocol = IPPROTO_ICMPV6;
	} else if (l4protocol == IPPROTO_ICMPV6) {
		l4protocol = IPPROTO_ICMP;
	} else if (!(l4protocol & NAT64_IPV6_ALLWD_PROTOS)) {
		pr_debug("NAT64: update n filter -> unkown L4 protocol");
		return NULL;
	}

	/*
	 //FIXME: No sirve para IPv6
	 pr_debug("NAT64: DEBUG: nat64_translate_packet()");
	 if (l3protocol == NFPROTO_IPV4 && !(nat64_get_tuple(l3protocol, l4protocol,
	 new_skb, outgoing))) {
	 pr_debug("NAT64: Something went wrong getting the tuple");
	 return NULL;
	 }
	 */

	pr_debug("NAT64: Packet translation successful.");

	return new_skb;
}

