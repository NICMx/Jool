#include "nat64/mod/ipv6_hdr_iterator.h"
#include <net/ipv6.h>


bool is_extension_hdr(__u8 header_id)
{
	return (header_id == NEXTHDR_HOP)
			|| (header_id == NEXTHDR_ROUTING)
			|| (header_id == NEXTHDR_FRAGMENT)
			|| (header_id == NEXTHDR_DEST)
			|| (header_id == NEXTHDR_AUTH)
			|| (header_id == NEXTHDR_ESP);
}

void hdr_iterator_init(struct hdr_iterator *iterator, struct ipv6hdr *main_hdr)
{
	struct hdr_iterator defaults = HDR_ITERATOR_INIT(main_hdr);
	memcpy(iterator, &defaults, sizeof(defaults));
}

enum hdr_iterator_result hdr_iterator_next(struct hdr_iterator *iterator)
{
	__u8 original_hdr_type = iterator->hdr_type;
	void *original_data = iterator->data;

	switch (iterator->hdr_type) {
	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_DEST: {
		struct ipv6_opt_hdr *hdr = iterator->data;
		iterator->hdr_type = hdr->nexthdr;
		iterator->data += 8 + 8 * hdr->hdrlen;
		break;
	}

	case NEXTHDR_FRAGMENT: {
		struct frag_hdr *hdr = iterator->data;
		iterator->hdr_type = hdr->nexthdr;
		iterator->data += sizeof(*hdr);
		break;
	}

	case NEXTHDR_AUTH:
	case NEXTHDR_ESP:
		/*
		 * I understand we're not supposed to support these (RFC 6146 section 5.1).
		 * If exthdrs_core.c is updated in kernel 3.5.0, the kernel doesn't support them either.
		 * I also don't understand how am I supposed to know the ESP header's length.
		 */
		return HDR_ITERATOR_UNSUPPORTED;

	default:
		return HDR_ITERATOR_END;
	}

	if (iterator->data >= iterator->limit) {
		iterator->hdr_type = original_hdr_type;
		iterator->data = original_data;
		return HDR_ITERATOR_OVERFLOW;
	}

	return HDR_ITERATOR_SUCCESS;
}

enum hdr_iterator_result hdr_iterator_last(struct hdr_iterator *iterator)
{
	enum hdr_iterator_result result;

	while ((result = hdr_iterator_next(iterator)) == HDR_ITERATOR_SUCCESS)
		/* Void on purpose. */;

	return result;
}

void *get_extension_header(struct ipv6hdr *ip6_hdr, __u8 hdr_id)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);

	if (!is_extension_hdr(hdr_id))
		return NULL;

	do {
		if (iterator.hdr_type == hdr_id)
			return iterator.data;
	} while (hdr_iterator_next(&iterator) == HDR_ITERATOR_SUCCESS);

	return NULL;
}
