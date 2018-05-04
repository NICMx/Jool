#include "expecter.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sort.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/address.h"
#include "util.h"

struct expecter_node {
	struct expected_packet pkt;
	struct list_head list_hook;
};

static LIST_HEAD(list);
static struct graybox_stats stats;

void expecter_setup(void)
{
	memset(&stats, 0, sizeof(stats));
}

void expecter_teardown(void)
{
	expecter_flush();
}

static void free_node(struct expecter_node *node)
{
	if (!node)
		return;

	if (node->pkt.exceptions)
		kfree(node->pkt.exceptions);
	if (node->pkt.bytes)
		kfree(node->pkt.bytes);
	if (node->pkt.filename)
		kfree(node->pkt.filename);
	kfree(node);
}

static int be16_compare(const void *a, const void *b)
{
	return *(__u16 *)a - *(__u16 *)b;
}

static void be16_swap(void *a, void *b, int size)
{
	__u16 t = *(__u16 *)a;
	*(__u16 *)a = *(__u16 *)b;
	*(__u16 *)b = t;
}

static void sort_exceptions(struct expected_packet *pkt)
{
	__u16 *list = pkt->exceptions;
	int list_length = pkt->exceptions_len;
	unsigned int i, j;

	/* Sort ascending. */
	sort(list, list_length, sizeof(*list), be16_compare, be16_swap);

	/* Remove duplicates. */
	for (i = 0, j = 1; j < list_length; j++) {
		if (list[i] != list[j]) {
			i++;
			list[i] = list[j];
		}
	}

	pkt->exceptions_len = i + 1;
}

int expecter_add(struct expected_packet *pkt)
{
	struct expecter_node *node;
	size_t exceptions_size;

	if (pkt->bytes_len == 0) {
		log_err("The packet is zero bytes long.");
		return -EINVAL;
	}

	node = kmalloc(sizeof(struct expecter_node), GFP_KERNEL);
	if (!node)
		goto enomem;
	memset(node, 0, sizeof(*node));

	node->pkt.filename = kmalloc(strlen(pkt->filename) + 1, GFP_KERNEL);
	if (!node->pkt.filename)
		goto enomem;
	strcpy(node->pkt.filename, pkt->filename);

	node->pkt.bytes = kmalloc(pkt->bytes_len, GFP_KERNEL);
	if (!node->pkt.bytes)
		goto enomem;
	memcpy(node->pkt.bytes, pkt->bytes, pkt->bytes_len);
	node->pkt.bytes_len = pkt->bytes_len;

	if (pkt->exceptions && pkt->exceptions_len) {
		exceptions_size = pkt->exceptions_len * sizeof(*pkt->exceptions);
		node->pkt.exceptions = kmalloc(exceptions_size, GFP_KERNEL);
		if (!node->pkt.exceptions)
			goto enomem;
		memcpy(node->pkt.exceptions, pkt->exceptions, exceptions_size);
		node->pkt.exceptions_len = pkt->exceptions_len;
		sort_exceptions(&node->pkt);
	}

	list_add_tail(&node->list_hook, &list);

	log_debug("Stored packet '%s'.", pkt->filename);
	return 0;

enomem:
	free_node(node);
	return -ENOMEM;
}

void expecter_flush(void)
{
	struct expecter_node *node;
	struct list_head *hook;

	while (!list_empty(&list)) {
		hook = list.next;
		list_del(hook);
		node = list_entry(hook, struct expecter_node, list_hook);

		switch (get_l3_proto(node->pkt.bytes)) {
		case 4:
			stats.ipv4.queued++;
			break;
		case 6:
			stats.ipv6.queued++;
			break;
		}

		free_node(node);
	}
}

static bool has_same_addr6(struct ipv6hdr *hdr1, struct ipv6hdr *hdr2)
{
	return addr6_equals(&hdr1->daddr, &hdr2->daddr)
			&& addr6_equals(&hdr1->saddr, &hdr2->saddr);
}

static bool has_same_addr4(struct iphdr *hdr1, struct iphdr *hdr2)
{
	return hdr1->daddr == hdr2->daddr && hdr1->saddr == hdr2->saddr;
}

static bool has_same_address(struct expected_packet *expected, struct sk_buff *actual)
{
	int expected_proto = get_l3_proto(expected->bytes);
	int actual_proto = get_l3_proto(skb_network_header(actual));

	if (expected_proto != actual_proto)
		return false;

	switch (expected_proto) {
	case 4:
		return has_same_addr4((struct iphdr *) expected->bytes,
				ip_hdr(actual));
	case 6:
		return has_same_addr6((struct ipv6hdr *) expected->bytes,
				ipv6_hdr(actual));
	}

	return false;
}

static void print_error_table_hdr(struct expected_packet *expected, int errors)
{
	if (!errors) {
		log_info("%s", expected->filename);
		log_info("    Value\tExpected    Actual");
	}
}

static bool pkt_equals(struct expected_packet *expected, struct sk_buff *actual)
{
	unsigned char *expected_ptr;
	unsigned char *actual_ptr;
	unsigned int i;
	unsigned int min_len;
	unsigned int skip_count;
	int errors = 0;

	if (expected->bytes_len != actual->len) {
		print_error_table_hdr(expected, errors);
		log_info("    Length\t%zu\t    %d", expected->bytes_len, actual->len);
		errors++;
	}

	expected_ptr = expected->bytes;
	actual_ptr = skb_network_header(actual);
	min_len = (expected->bytes_len < actual->len) ? expected->bytes_len : actual->len;

	skip_count = 0;

	for (i = 0; i < min_len; i++) {
		if (skip_count < expected->exceptions_len && expected->exceptions[skip_count] == i) {
			skip_count++;
			continue;
		}

		if (expected_ptr[i] != actual_ptr[i]) {
			print_error_table_hdr(expected, errors);
			log_info("    byte %u\t0x%x\t    0x%x", i,
					expected_ptr[i], actual_ptr[i]);
			errors++;
			if (errors >= 8)
				break;
		}
	}

	return !errors;
}

static struct graybox_proto_stats *get_stats(struct expected_packet *pkt)
{
	switch (get_l3_proto(pkt->bytes)) {
	case 4:
		return &stats.ipv4;
	case 6:
		return &stats.ipv6;
	}

	return NULL;
}

int expecter_handle_pkt(struct sk_buff *actual)
{
	struct expecter_node *node;
	struct expected_packet *expected;
	struct graybox_proto_stats *stats;

	if (list_empty(&list)) /* nothing to do. */
		return NF_ACCEPT;

	node = list_entry(list.next, struct expecter_node, list_hook);
	expected = &node->pkt;

	if (!has_same_address(expected, actual))
		return NF_ACCEPT;

	list_del(&node->list_hook);

	log_debug("Received packet matches '%s'.", expected->filename);

	stats = get_stats(expected);
	if (WARN(!stats, "Unreachable code: protocol was already validated."))
		return NF_ACCEPT;

	if (pkt_equals(expected, actual)) {
		stats->successes++;
	} else {
		stats->failures++;
	}

	free_node(node);
	return NF_DROP;
}

void expecter_stat(struct graybox_stats *result)
{
	struct expecter_node *node;
	struct list_head *hook;

	memcpy(result, &stats, sizeof(stats));

	list_for_each(hook, &list) {
		node = list_entry(hook, struct expecter_node, list_hook);
		switch (get_l3_proto(node->pkt.bytes)) {
		case 4:
			result->ipv4.queued++;
			break;
		case 6:
			result->ipv6.queued++;
			break;
		}
	}
}

void expecter_stat_flush(void)
{
	memset(&stats, 0, sizeof(stats));
}
