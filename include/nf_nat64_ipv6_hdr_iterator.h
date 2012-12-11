#ifndef NF_NAT64_IPV6_HDR_ITERATOR_H_
#define NF_NAT64_IPV6_HDR_ITERATOR_H_

/**
 * @file
 * Routines and structures that help traverse the extension headers of IPv6 packets.
 *
 * Everything in this file assumes the main IPv6 header is glued in memory to the extension headers,
 * preceding them (such as in a linearized sk_buff).
 */

#include <linux/kernel.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>


/**
 * An object that helps you traverse the IPv6 headers of a packet.
 */
struct hdr_iterator
{
	/**
	 * Type of the header we're currently visiting.
	 * If -1, "data" is the IPv6 header.
	 * If anything else, "data" holds the previous header's nexthdr value.
	 */
	__s16 hdr_type;
	/**
	 * If we're still iterating through headers, this is the header we're currently visiting
	 * (you'll need to cast it into something).
	 * If we're not, this is the payload.
	 */
	void *data;
};


/**
 * Use this to initialize your "hdr_iterator".
 *
 * @param main_hdr The IPv6 header whose subheaders you want to traverse.
 * @return a initialized "hdr_iterator".
 */
#define HDR_ITERATOR_INIT(main_hdr) { -1, main_hdr }

/**
 * Returns "true" if the nexthdr value "header_id" is considered an extension header, as defined by
 * RFC 2460 section 4.
 *
 * @param header type you want to test.
 * @return whether "header_id" is an extension header or not.
 */
bool is_extension_hdr(__u8 header_id);
/**
 * Use this to initialize your "hdr_iterator".
 *
 * @param iterator The "hdr_iterator" you want to initialize.
 * @param main_hdr The IPv6 header whose subheaders you want to traverse.
 */
void hdr_iterator_init(struct hdr_iterator *iterator, struct ipv6hdr *main_hdr);
/**
 * Advances "iterator->hdr" one header and updates "iterator->hdr_type" accordingly. If "iterator"
 * has already reached the payload, nothing will happen.
 *
 * @param iterator iterator you want to move to the next header.
 * @return "true" if advancement was successful, "false" if payload found.
 */
bool hdr_iterator_next(struct hdr_iterator *iterator);
/**
 * Advances "iterator" to the end of the header chain. That is, leaves the pointer at the layer 3
 * payload.
 *
 * @param iterator iterator you want to move to the end of its chain.
 */
void hdr_iterator_last(struct hdr_iterator *iterator);
/**
 * Internally uses an iterator to reach and return header "hdr_id" from "ip6_hdr"'s extension
 * headers.
 *
 * @param ip6_hdr fixed header from the packet you want the extension header from.
 * @param hdr_id header type you want.
 * @return header whose ID is "hdr_id" from "ip6_hdr"'s extension headers. Returns "NULL" if the
 *			header chains does not contain such a header.
 */
void *get_extension_header(struct ipv6hdr *ip6_hdr, __u8 hdr_id);

#endif /* NF_NAT64_IPV6_HDR_ITERATOR_H_ */
