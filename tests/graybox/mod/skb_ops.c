#include "skb_ops.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>

#include "types.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "send_packet.h"

struct bytes {
	/* The byte position to skip at skb_comparison(). */
	__u16 *array;
	/* The number of integers in the array. */
	__u16 count;
};

static struct bytes *bytes_to_skip;

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
	struct iphdr *hdr4 = pkt;

	switch (get_l3_proto(pkt)) {
	case 6:
		hdr_iterator_last(&iterator);
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
	struct bytes skip_byte;
	unsigned char *expected_ptr, *actual_ptr;
	unsigned int i, min_len, skip_count;
	int errors = 0;

	log_debug("Comparing incoming packet");
	if (expected->len != actual->len) {
		log_err("skb length is different, expected %d. actual %d.", expected->len, actual->len);
		errors++;
	}

	expected_ptr = (unsigned char *) skb_network_header(expected);
	actual_ptr = (unsigned char *) skb_network_header(actual);
	min_len = (expected->len < actual->len) ? expected->len : actual->len;

	rcu_read_lock_bh();
	skip_byte = *(rcu_dereference_bh(bytes_to_skip));
	skip_count = 0;

	for (i = 0; i < min_len; i++) {
		if (skip_count < skip_byte.count && skip_byte.array[skip_count] == i) {
			skip_count++;
			continue;
		}

		if (expected_ptr[i] != actual_ptr[i]) {
			log_err("Packets differ at byte %u. Expected: 0x%x; actual: 0x%x.",
					i, expected_ptr[i], actual_ptr[i]);
			errors++;
		}
	}

	*err += errors;

	rcu_read_unlock_bh();
	return !errors;
}

void skb_free(struct sk_buff *skb)
{
	kfree_skb(skb);
}

int skbops_init(void)
{
	bytes_to_skip = kmalloc(sizeof(struct bytes), GFP_ATOMIC);
	if (!bytes_to_skip)
		return -ENOMEM;

	bytes_to_skip->array = NULL;
	bytes_to_skip->count = 0;

	return 0;
}

void skbops_destroy(void)
{
	if (bytes_to_skip->array)
		kfree(bytes_to_skip->array);

	kfree(bytes_to_skip);
}

int update_bytes_array(void *values, size_t size)
{
	struct bytes *tmp, *old;
	__u16 *list = values;
	unsigned int count = size / 2;
	unsigned int i, j;

	if (!values) {
		log_err("Values cannot be NULL");
		return -EINVAL;
	}

	if (count == 0) {
		log_err("The bytes list received from userspace is empty.");
		return -EINVAL;
	}
	if (size % 2 == 1) {
		log_err("Expected an array of 16-bit integers; got an uneven number of bytes.");
		return -EINVAL;
	}

	tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		log_err("Could not allocate struct bytes.");
		return -ENOMEM;
	}

	old = bytes_to_skip;
	*tmp = *bytes_to_skip;

	/* Remove zeroes and duplicates. */
	for (i = 0, j = 1; j < count; j++) {
		if (list[j] == 0)
			break;
		if (list[i] != list[j]) {
			i++;
			list[i] = list[j];
		}
	}

	count = i + 1;
	size = count * sizeof(*list);

	/* Update. */
	tmp->array = kmalloc(size, GFP_KERNEL);
	if (!tmp->array) {
		log_err("Could not allocate the byte array list.");
		return -ENOMEM;
	}
	memcpy(tmp->array, list, size);
	tmp->count = count;

	rcu_assign_pointer(bytes_to_skip, tmp);
	synchronize_rcu_bh();

	if (old->array && tmp->array != old->array)
		kfree(old->array);

	kfree(old);
	return 0;
}

int flush_bytes_array(void)
{
	struct bytes *tmp, *old;

	rcu_read_lock_bh();
	if (!(rcu_dereference_bh(bytes_to_skip)->array)) {
		log_info("Byte array list is empty nothing to flush");
		rcu_read_unlock_bh();
		return 0;
	}
	rcu_read_unlock_bh();

	tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp) {
		log_err("Could not allocate struct bytes.");
		return -ENOMEM;
	}

	old = bytes_to_skip;
	*tmp = *bytes_to_skip;

	/* Delete. */
	tmp->array = NULL;
	tmp->count = 0;

	rcu_assign_pointer(bytes_to_skip, tmp);
	synchronize_rcu_bh();

	if (old->array)
		kfree(old->array);

	kfree(old);
	return 0;
}

int display_bytes_array(void)
{
	struct bytes tmp;
	int i;

	rcu_read_lock_bh();
	tmp = *rcu_dereference(bytes_to_skip);

	if (!tmp.count) {
		log_info("Byte array list is empty");
		goto end;
	}

	for (i = 0; i < tmp.count; i++) {
		if (i + 1 != tmp.count)
			printk("%u, ", tmp.array[i]);
		else
			printk("%u\n", tmp.array[i]);
	}
	log_info("Array length: %d", tmp.count);

end:
	rcu_read_unlock_bh();
	return 0;
}
