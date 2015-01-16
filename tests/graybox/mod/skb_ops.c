#include "skb_ops.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>

#include "types.h"
#include "ipv6_hdr_iterator.h"
#include "send_packet.h"

static bool has_same_ipv6_address(struct ipv6hdr *expected, struct ipv6hdr *actual)
{
	int gap;

	log_debug(" ====================");
	log_debug("Comparing Adresses:");
	log_debug("Expected src = %pI6c, dst = %pI6c", &expected->saddr, &expected->daddr);
	log_debug("Actual src = %pI6c, dst = %pI6c", &actual->saddr, &actual->daddr);
	log_debug(" ====================");

	gap = ipv6_addr_cmp(&expected->daddr, &actual->daddr);
	if (gap)
		return false;

	gap = ipv6_addr_cmp(&expected->saddr, &actual->saddr);
	if (gap)
		return false;

	return true;
}

static bool has_same_ipv4_address(struct iphdr *expected, struct iphdr *actual)
{
	log_debug(" ====================");
	log_debug("Comparing Addresses:");
	log_debug("Expected = src: %pI4 , dst: %pI4",&expected->saddr, &expected->daddr);
	log_debug("Actual = src: %pI4 , dst: %pI4",&actual->saddr, &actual->daddr);
	log_debug("=====================");

	if (expected->daddr != actual->daddr)
		return false;
	if (expected->saddr != actual->saddr)
		return false;

	if (actual->protocol != expected->protocol) {
		log_debug("Has same address but different protocol, try with another one.");
		return false;
	}

	return true;
}


/*
 * Size includes fragment header if packet is IPv6.
 */
static int net_hdr_size(void *pkt)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT((struct ipv6hdr *) pkt);
	enum hdr_iterator_result result;
	struct iphdr *hdr4 = pkt;

	switch (get_l3_proto(pkt)) {
	case 6:
		result = hdr_iterator_last(&iterator);
		if (result != HDR_ITERATOR_END) {
			log_err("Invalid network header found while iterating.");
			return -EINVAL;
		}
		return iterator.data - pkt;

	case 4:
		return (hdr4->ihl << 2);

	default:
		log_err("Invalid mode: %u", get_l3_proto(pkt));
		return -EINVAL;
	}
}

int skb_from_pkt(void *pkt, u32 pkt_len, struct sk_buff **skb)
{
	log_debug("Creating the skb from userspace...");
	*skb = alloc_skb(LL_MAX_HEADER + pkt_len, GFP_ATOMIC);
	if (!*skb) {
		log_err("Could not allocate a skb.");
		return -ENOMEM;
	}

	skb_reserve(*skb, LL_MAX_HEADER); /* Reserve space for Link Layer data. */
	skb_put(*skb, pkt_len); /* L3 + L4 + payload. */

	skb_set_mac_header(*skb, 0);
	skb_set_network_header(*skb, 0);
	skb_set_transport_header(*skb, net_hdr_size(pkt));

	(*skb)->ip_summed = CHECKSUM_UNNECESSARY;
	switch (get_l3_proto(pkt)) {
	case 6:
		(*skb)->protocol = htons(ETH_P_IPV6);
		break;
	case 4:
		(*skb)->protocol = htons(ETH_P_IP);
		break;
	default:
		log_err("Invalid mode: %u.", get_l3_proto(pkt));
		kfree_skb(*skb);
		return -EINVAL;
	}

	/* Copy packet content to skb. */
	memcpy(skb_network_header(*skb), pkt, pkt_len);

	return 0;
}

int skb_route(struct sk_buff *skb, void *pkt)
{
	struct dst_entry *dst;

	log_debug("Routing packet...");
	switch (get_l3_proto(pkt)) {
	case 6:
		dst = route_ipv6(pkt);
		break;
	case 4:
		dst = route_ipv4(pkt);
		break;
	default:
		log_err("Invalid mode: %u", get_l3_proto(pkt));
		return -EINVAL;
	}

	if (!dst)
		return -EINVAL;

	(skb)->dev = dst->dev;
	skb_dst_set(skb, dst);

	return 0;
}


bool skb_has_same_address(struct sk_buff *expected, struct sk_buff *actual)
{
	if (expected->protocol != actual->protocol) {
		log_err("skb doesnt have the same protocol");
		return false;
	}

	if (actual->protocol == htons(ETH_P_IP))
		return has_same_ipv4_address(ip_hdr(expected), ip_hdr(actual));
	else if (actual->protocol == htons(ETH_P_IPV6))
		return has_same_ipv6_address(ipv6_hdr(expected), ipv6_hdr(actual));

	return false;
}

bool skb_compare(struct sk_buff *expected, struct sk_buff *actual, int *err)
{
	unsigned char *expected_ptr, *actual_ptr;
	unsigned int i, min_len;
	int errors = 0;

	log_debug("Comparing incoming packet");
	if (expected->len != actual->len) {
		log_err("skb length is different, expected %d. actual %d.", expected->len, actual->len);
		errors++;
	}

	expected_ptr = (unsigned char *) skb_network_header(expected);
	actual_ptr = (unsigned char *) skb_network_header(actual);
	min_len = (expected->len < actual->len) ? expected->len : actual->len;

	for (i = 0; i < min_len; i++) {
		/*
		 * Skip the fragment identifier on IPv6 packets.
		 * This is because this value is random after translation most of the time.
		 * TODO (test) maybe make it possible to not do this on certain tests?
		 */
		if (44 <= i && i <= 47
				&& actual->protocol == ntohs(ETH_P_IPV6)
				&& ipv6_hdr(actual)->nexthdr == NEXTHDR_FRAGMENT)
			continue;

		if (expected_ptr[i] != actual_ptr[i]) {
			log_err("Packets differ at byte %u. Expected: 0x%x; actual: 0x%x.",
					i, expected_ptr[i], actual_ptr[i]);
			errors++;
		}
	}

	*err += errors;

	return !errors;
}

void skb_free(struct sk_buff *skb)
{
	kfree_skb(skb);
}

