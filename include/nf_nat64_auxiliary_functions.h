/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Authors:
 *	Representative NIC-Mx
 *	Ing. Gustavo Lozano <glozano@nic.mx>
 *	Ing. Jorge Cano
 *
 *	Representative ITESM
 *	Dr. Juan Arturo Nolazco	<jnolazco@itesm.mx>
 *	Ing. Martha Sordia <msordia@itesm.mx>
 *
 *	Students ITESM
 *	Juan Antonio Osorio <jaosorior@gmail.com>
 *	Luis Fernando Hinojosa <lf.hinojosa@gmail.com>
 *	David Valenzuela <david.valenzuela.88@gmail.com>
 *	Jose Vicente Ramirez <pepermz@gmail.com>
 *	Mario Gerardo Trevinho <mario_tc88@hotmail.com>
 *	Roberto Aceves <roberto.aceves@gmail.com>
 *	Miguel Alejandro González <maggonzz@gmail.com>
 *	Ramiro Nava <ramironava@gmail.com>
 *	Adrian González <bernardogzzf@gmail.com>
 *	Manuel Aude <dormam@gmail.com>
 *	Gabriel Chavez <gabrielchavez02@gmail.com>
 *	Alan Villela López <avillop@gmail.com>
 *	  
 *	  The rest of us, I propose include our names and order all alphabetically.
 *
 * Authors of the ip_data, checksum_adjust, checksum_remove, checksum_add
 * checksum_change, adjust_checksum_ipv6_to_ipv4, nat64_output_ipv4, 
 * adjust_checksum_ipv4_to_ipv6, nat64_xlate_ipv6_to_ipv4, nat64_alloc_skb,
 * nat64_xlate_ipv4_to_ipv6 functions that belong to the Ecdysis project:
 *	Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *	Simon Perreault <simon.perreault@viagenie.ca>
 *	Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 *	Ecdysis <http://ecdysis.viagenie.ca/>
 *
 * The previous functions are found in the nf_nat64_main.c file of Ecdysis's 
 * NAT64 implementation.
 *
 * Please note: 
 * The function nat64_output_ipv4 was renamed as nat64_send_packet_ipv4 
 * under the kernel version that is inferior to 3.0 in this 
 * implementation. The function nat64_send_packet_ipv6 for both
 * kernel versions were based on this function.
 *
 * The functions nat64_xlate_ipv6_to_ipv4 and nat64_xlate_ipv4_to_ipv6 were
 * used as a point of reference to implement nat64_get_skb_from6to4 and
 * nat64_get_skb_from4to6, respectively. Furthermore, nat64_alloc_skb was
 * also used as a point of reference to implement nat64_get_skb.
 * 
 * Author of the nat64_extract_ipv4, nat64_allocate_hash, tcp_timeout_fsm,
 * tcp4_fsm, tcp6_fsm, bib_allocate_local4_port, bib_ipv6_lookup, bib_ipv4_lookup,
 * bib_create, bib_session_create, session_ipv4_lookup, session_renew,
 * session_create, clean_expired_sessions functions, nat64_ipv6_input:
 *	Julius Kriukas <julius.kriukas@gmail.com>
 * 
 * 	Linux NAT64 <http://ipv6.lt/nat64_en.php>
 *
 * The previous functions are found in the nat64_session.c and nat64_core.c
 * files of Julius Kriukas's Linux NAT64 implementation. Furthermore, these
 * functions used global variables which were added (with a comment indicating
 * their origin) in our xt_nat64.c file. The majority of these functions can 
 * be found in our nf_nat64_filtering_and_updating.h file. Not all of them are 
 * being used in this release version but are planned to be used in the future.
 * This is the case of the tcp4_fsm, tcp6_fsm, tcp_timeout_fsm and 
 * clean_expired_sessions functions and some of the global variables they use.
 * Part of our nat64_filtering_and_updating function was based on Julius's 
 * implementation of his nat64_ipv6_input function.
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#ifndef _NF_NAT64_AUXILIARY_FUNCTIONS_H
#define _NF_NAT64_AUXILIARY_FUNCTIONS_H
/*
 * BEGIN: Packet Auxiliary Functions
 */

/*
 * Function that retrieves a pointer to the Layer 4 header.
 */
static inline void * ip_data(struct iphdr *ip4)
{
	return (char *)ip4 + ip4->ihl*4;
}

/*
 * Function that gets the Layer 4 header length.
 */
static inline int nat64_get_l4hdrlength(u_int8_t l4protocol)
{
	switch(l4protocol) {
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
 * Function to get the Layer 3 header length.
 */
static inline int nat64_get_l3hdrlen(struct sk_buff *skb, u_int8_t l3protocol)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			pr_debug("NAT64 get_l3hdrlen is IPV4");
			return ip_hdrlen(skb);
		case NFPROTO_IPV6:
			pr_debug("NAT64 get_l3hdrlen is IPV6");
			return (skb_network_offset(skb) + 
					sizeof(struct ipv6hdr));
		default:
			return -1;
	}
}

/*
 * BEGIN SUBSECTION: ECDYSIS FUNCTIONS
 */

static inline 
void checksum_adjust(uint16_t *sum, uint16_t old, uint16_t new, bool udp)
{
	uint32_t s;

	if (udp && !*sum)
		return;

	s = *sum + old - new;
	*sum = (s & 0xffff) + (s >> 16);

	if (udp && !*sum)
		*sum = 0xffff;
}

static inline void checksum_remove(uint16_t *sum, uint16_t *begin, 
				uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, *begin++, 0, udp);
}

static inline void checksum_add(uint16_t *sum, uint16_t *begin, 
				uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, 0, *begin++, udp);
}

static inline void checksum_change(uint16_t *sum, uint16_t *x, 
				uint16_t new, bool udp)
{
	checksum_adjust(sum, *x, new, udp);
	*x = new;
}

static inline void adjust_checksum_ipv6_to_ipv4(uint16_t *sum, struct ipv6hdr *ip6, 
		struct iphdr *ip4, bool udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);
}

static inline void adjust_checksum_ipv4_to_ipv6(uint16_t *sum, 
												struct iphdr *ip4, 
												struct ipv6hdr *ip6, int udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);
}


/*
 * END SUBSECTION: ECDYSIS FUNCTIONS
 */

/*
 * END: Packet Auxiliary Functions
 */
#endif /* _NF_NAT64_AUXILIARY_FUNCTIONS_H */
