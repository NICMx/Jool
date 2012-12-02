#include <linux/kernel.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#include "nf_nat64_ipv6_hdr_iterator.h"

bool is_extension_hdr(__u8 header_id)
{
	return (header_id == NEXTHDR_HOP) //
			|| (header_id == NEXTHDR_ROUTING) //
			|| (header_id == NEXTHDR_FRAGMENT) //
			|| (header_id == NEXTHDR_DEST) //
			|| (header_id == NEXTHDR_AUTH) //
			|| (header_id == NEXTHDR_ESP);
}

void hdr_iterator_init(struct hdr_iterator *iterator, struct ipv6hdr *main_hdr)
{
	struct hdr_iterator defaults = HDR_ITERATOR_INIT(main_hdr);
	iterator->hdr_type = defaults.hdr_type;
	iterator->data = defaults.data;
}

bool hdr_iterator_next(struct hdr_iterator *iterator)
{
	if (iterator->hdr_type != -1 && !is_extension_hdr(iterator->hdr_type))
		return false;

	switch (iterator->hdr_type) {
	case -1: {
		struct ipv6hdr *hdr = iterator->data;
		iterator->hdr_type = hdr->nexthdr;
		iterator->data += sizeof(*hdr);
		return true;
	}

	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_DEST: {
		struct ipv6_opt_hdr *hdr = iterator->data;
		iterator->hdr_type = hdr->nexthdr;
		iterator->data += 8 + 8 * hdr->hdrlen;
		return true;
	}

	case NEXTHDR_FRAGMENT: {
		struct frag_hdr *hdr = iterator->data;
		iterator->hdr_type = hdr->nexthdr;
		iterator->data += sizeof(*hdr);
		return true;
	}

	case NEXTHDR_AUTH:
	case NEXTHDR_ESP:
		// I understand we're not supposed to support these (RFC 6146 section 5.1).
		// If exthdrs_core.c is updated in kernel 3.5.0, the kernel doesn't support them either.
		// I also don't understand how am I supposed to know the ESP header's length.
		return false;
	}

	pr_crit("hdr_iterator_next - Programming error: Unknown hdr: %d.\n", iterator->hdr_type);
	return false;
}

void hdr_iterator_last(struct hdr_iterator *iterator)
{
	while (hdr_iterator_next(iterator))
		/* Void on purpose. */;
}

void *get_extension_header(struct ipv6hdr *ip6_hdr, __u8 hdr_id)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);

	if (!is_extension_hdr(hdr_id))
		return NULL;

	while (hdr_iterator_next(&iterator))
		if (iterator.hdr_type == hdr_id)
			return iterator.data;

	return NULL;
}
