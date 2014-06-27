#ifndef _JOOL_MOD_IPV6_HDR_ITERATOR_H
#define _JOOL_MOD_IPV6_HDR_ITERATOR_H

/**
 * @file
 * Routines and structures that help traverse the extension headers of IPv6 packets.
 *
 * Everything in this file assumes the main IPv6 header is glued in memory to the extension headers,
 * preceding them (such as in a linearized sk_buff).
 *
 * @author Alberto Leiva
 */

#include <linux/types.h>
#include <linux/ipv6.h>


/**
 * An object that helps you traverse the IPv6 headers of a packet.
 */
struct hdr_iterator {
	/** Type of the header we're currently visiting (previous header's nexthdr value). */
	__u8 hdr_type;
	/**
	 * Header we're currently visiting. Might also be the payload, if the iteration ended.
	 * You can know what's here by querying "hdr_type".
	 */
	void *data;
	/**
	 * Pointer to the last byte the iterator can step through (i. e. the end of the packet).
	 * If "data" surpasses this, the iterator will refuse further movement.
	 */
	void *limit;
};

typedef enum hdr_iterator_result {
	/** The iterator managed to advance one header. */
	HDR_ITERATOR_SUCCESS,
	/** The iterator reached the payload. */
	HDR_ITERATOR_END,
	/** Further movement is prevented by a unsupported header type (Auth or ESP). */
	HDR_ITERATOR_UNSUPPORTED,
	/** The packet seems truncated, so the iterator won't move anymore. */
	HDR_ITERATOR_OVERFLOW
} hdr_iterator_result;


/**
 * Use this to initialize your "hdr_iterator".
 *
 * @param main_hdr The IPv6 header whose subheaders you want to traverse.
 * @return a initialized "hdr_iterator".
 */
#define HDR_ITERATOR_INIT(main_hdr) { \
	.hdr_type = (main_hdr)->nexthdr, \
	.data = (main_hdr) + 1, \
	.limit = ((void *) ((main_hdr) + 1)) + be16_to_cpu((main_hdr)->payload_len) \
}

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
 * @return result status.
 */
enum hdr_iterator_result hdr_iterator_next(struct hdr_iterator *iterator);
/**
 * Advances "iterator" to the end of the header chain. That is, leaves the pointer at the layer 3
 * payload.
 *
 * @param iterator iterator you want to move to the end of its chain.
 * @return result status.
 */
enum hdr_iterator_result hdr_iterator_last(struct hdr_iterator *iterator);

/**
 * Internally uses an iterator to reach and return header "hdr_id" from "ip6_hdr"'s extension
 * headers.
 * *Does not return iteration status, so use only when the packet is known to be valid*
 *
 * @param ip6_hdr fixed header from the packet you want the extension header from.
 * @param hdr_id header type you want.
 * @return header whose ID is "hdr_id" from "ip6_hdr"'s extension headers. Returns "NULL" if the
 *			header chains does not contain such a header (or the iteration ended for some other
 *			reason).
 */
void *get_extension_header(struct ipv6hdr *ip6_hdr, __u8 hdr_id);

#endif /* _JOOL_MOD_IPV6_HDR_ITERATOR_H */
