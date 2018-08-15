#include "nat64/mod/common/skbuff.h"

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/printk.h>
#include <net/ipv6.h>

#include "nat64/mod/common/packet.h"

enum hdr_protocol {
	HP_IPV4 = 4,
	HP_IPV6 = 128,
	HP_TCP = NEXTHDR_TCP,
	HP_UDP = NEXTHDR_UDP,
	HP_ICMP4 = IPPROTO_ICMP,
	HP_ICMP6 = NEXTHDR_ICMP,
	HP_HOP = NEXTHDR_HOP,
	HP_ROUTING = NEXTHDR_ROUTING,
	HP_DEST = NEXTHDR_DEST,
	HP_FRAG = NEXTHDR_FRAGMENT,
	HP_PAYLOAD = 129,
};

struct hdr_iterator {
	unsigned int tabs;
	void *ptr;
	enum hdr_protocol type;
	bool done;
};

#define print(tabs, text, ...) do { \
		print_tabs(tabs); \
		pr_cont(text "\n", ##__VA_ARGS__); \
	} while (0)

static void __skb_log(struct sk_buff *skb, char *header, unsigned int tabs);

static void print_tabs(unsigned int tabs)
{
	unsigned int t;

	pr_info("");
	for (t = 0; t < tabs; t++)
		pr_cont("    ");
}

static char *skbproto2string(__u16 proto)
{
	switch (proto) {
	case ETH_P_IP:
		return "IPv4";
	case ETH_P_IPV6:
		return "IPv6";
	}

	return "unknown";
}

static char *ipsummed2string(__u8 ip_summed)
{
	switch (ip_summed) {
	case CHECKSUM_NONE:
		return "CHECKSUM_NONE";
	case CHECKSUM_UNNECESSARY:
		return "CHECKSUM_UNNECESSARY";
	case CHECKSUM_COMPLETE:
		return "CHECKSUM_COMPLETE";
	case CHECKSUM_PARTIAL:
		return "CHECKSUM_PARTIAL";
	}

	return "unknown";
}

static void print_skb_fields(struct sk_buff *skb, unsigned int tabs)
{
	__u16 proto;

	print(tabs++, "skb fields:");
	print(tabs, "prev:%p", skb->prev);
	print(tabs, "next:%p", skb->next);
	print(tabs, "dev:%p", skb->dev);
	print(tabs, "len:%u", skb->len);
	print(tabs, "data_len:%u", skb->data_len);
	print(tabs, "mac_len:%u", skb->mac_len);
	print(tabs, "hdr_len:%u", skb->hdr_len);
	print(tabs, "truesize:%u", skb->truesize);
	print(tabs, "pkt_type:%u", skb->pkt_type);
	print(tabs, "ignore_df:%u", skb->ignore_df);
	print(tabs, "ip_summed:%u (%s)", skb->ip_summed,
			ipsummed2string(skb->ip_summed));
	print(tabs, "csum_valid:%u", skb->csum_valid);
	print(tabs, "csum_bad:%u", skb->csum_bad);
	print(tabs, "csum_start:%u", skb->csum_start);
	print(tabs, "csum_offset:%u", skb->csum_offset);
	print(tabs, "mark:%u", skb->mark);
	print(tabs, "inner_transport_header:%u", skb->inner_transport_header);
	print(tabs, "inner_network_header:%u", skb->inner_network_header);
	print(tabs, "inner_mac_header:%u", skb->inner_mac_header);

	proto = be16_to_cpu(skb->protocol);
	print(tabs, "protocol:%u (%s)", proto, skbproto2string(proto));

	print(tabs, "transport_header:%u", skb->transport_header);
	print(tabs, "network_header:%u", skb->network_header);
	print(tabs, "mac_header:%u", skb->mac_header);
	print(tabs, "head:%p", skb->head);
	print(tabs, "data:%ld", skb->data - skb->head);
	print(tabs, "tail:%u", skb->tail);
	print(tabs, "end:%u", skb->end);
}

static void print_ipv4_hdr(struct hdr_iterator *meta)
{
	struct iphdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "IPv4 header:");
	print(tabs, "Version: %u", hdr->version);
	print(tabs, "IHL: %u", hdr->ihl);
	print(tabs, "TOS: %u", hdr->tos);
	print(tabs, "Total Length: %u", be16_to_cpu(hdr->tot_len));
	print(tabs, "Fragment ID: %u", be16_to_cpu(hdr->id));
	print(tabs, "Reserved:%u DF:%u MF:%u FragmentOffset: %u",
			be16_to_cpu(hdr->frag_off) >> 15,
			!!is_df_set(hdr),
			!!is_mf_set_ipv4(hdr),
			get_fragment_offset_ipv4(hdr));
	print(tabs, "TTL: %u", hdr->ttl);
	print(tabs, "Protocol: %u", hdr->protocol);
	print(tabs, "Checksum: %u", hdr->check);
	print(tabs, "Source Address: %pI4", &hdr->saddr);
	print(tabs, "Destination Address: %pI4", &hdr->daddr);

	meta->ptr = hdr + 1;
	meta->type = hdr->protocol;
}

static void print_ipv6_hdr(struct hdr_iterator *meta)
{
	struct ipv6hdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "IPv6 header:");
	print(tabs, "Version: %u", hdr->version);
	print(tabs, "Priority: %u", hdr->priority);
	print(tabs, "Flow Label: %u %u %u", hdr->flow_lbl[0], hdr->flow_lbl[1],
			hdr->flow_lbl[2]);
	print(tabs, "Payload Length: %u", be16_to_cpu(hdr->payload_len));
	print(tabs, "Next Header: %u", hdr->nexthdr);
	print(tabs, "Hop Limit: %u", hdr->hop_limit);
	print(tabs, "Source Address: %pI6c", &hdr->saddr);
	print(tabs, "Destination Address: %pI6c", &hdr->daddr);

	meta->ptr = hdr + 1;
	meta->type = hdr->nexthdr;
}

static void print_tcphdr(struct hdr_iterator *meta)
{
	struct tcphdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "TCP header:");
	print(tabs, "Src Port: %u", be16_to_cpu(hdr->source));
	print(tabs, "Dst Port: %u", be16_to_cpu(hdr->dest));
	print(tabs, "Seq Number: %u", be32_to_cpu(hdr->seq));
	print(tabs, "ACK Seq: %u", be32_to_cpu(hdr->ack_seq));
	print(tabs, "ACK:%u RST:%u SYN:%u FIN:%u",
			hdr->ack, hdr->rst, hdr->syn, hdr->fin);
	print(tabs, "[Other flags ommitted]");
	print(tabs, "Window Size: %u", be16_to_cpu(hdr->window));
	print(tabs, "Checksum: %u", hdr->check);
	print(tabs, "Urgent Pointer: %u", be16_to_cpu(hdr->urg_ptr));

	meta->ptr = hdr + 1;
	meta->type = HP_PAYLOAD;
}

static void print_udphdr(struct hdr_iterator *meta)
{
	struct udphdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "UDP header:");
	print(tabs, "Src Port: %u", be16_to_cpu(hdr->source));
	print(tabs, "Dst Port: %u", be16_to_cpu(hdr->dest));
	print(tabs, "Length: %u", be16_to_cpu(hdr->len));
	print(tabs, "Checksum: %u", be16_to_cpu(hdr->check));

	meta->ptr = hdr + 1;
	meta->type = HP_PAYLOAD;
}

static void print_icmp4hdr(struct hdr_iterator *meta)
{
	struct icmphdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "ICMPv4 header:");
	print(tabs, "Type:%u Code:%u", hdr->type, hdr->code);
	print(tabs, "Checksum: %u", be16_to_cpu(hdr->checksum));
	print(tabs, "Rest 1: %u", be16_to_cpu(hdr->un.echo.id));
	print(tabs, "Rest 2: %u", be16_to_cpu(hdr->un.echo.sequence));

	meta->ptr = hdr + 1;
	meta->type = is_icmp4_error(hdr->type) ? HP_IPV4 : HP_PAYLOAD;

}

static void print_icmp6hdr(struct hdr_iterator *meta)
{
	struct icmp6hdr *hdr = meta->ptr;
	unsigned int tabs = meta->tabs;

	print(tabs++, "ICMPv6 header:");
	print(tabs, "Type:%u Code:%u", hdr->icmp6_type, hdr->icmp6_code);
	print(tabs, "Checksum: %u", be16_to_cpu(hdr->icmp6_cksum));
	print(tabs, "Rest 1: %u", be16_to_cpu(hdr->icmp6_identifier));
	print(tabs, "Rest 2: %u", be16_to_cpu(hdr->icmp6_sequence));

	meta->ptr = hdr + 1;
	meta->type = is_icmp6_error(hdr->icmp6_type) ? HP_IPV4 : HP_PAYLOAD;
}

static void print_exthdr(struct hdr_iterator *meta)
{
	unsigned int tabs = meta->tabs;
	__u8 nexthdr;
	__u8 len;

	nexthdr = *((__u8 *)meta->ptr);
	len = *((__u8 *)meta->ptr + 1);
	len = 8 + 8 * len;

	print(tabs++, "IPv6 Extension header:");
	print(tabs, "Next Header: %u", nexthdr);
	print(tabs, "Length: %u", len);

	meta->ptr += len;
	meta->type = nexthdr;
}

static void print_fraghdr(struct hdr_iterator *meta)
{
	unsigned int tabs = meta->tabs;
	struct frag_hdr *hdr = meta->ptr;

	print(tabs++, "Fragment Header:");
	print(tabs, "Next Header: %u", hdr->nexthdr);
	print(tabs, "Reserved: %u", hdr->reserved);
	print(tabs, "FragmentOffset:%u Res:%u M:%u",
			get_fragment_offset_ipv6(hdr),
			(be16_to_cpu(hdr->frag_off) >> 1) & 3,
			is_mf_set_ipv6(hdr));
	print(tabs, "Identification: %u", be32_to_cpu(hdr->identification));

	meta->type = hdr->nexthdr;
	meta->ptr += sizeof(struct frag_hdr);
}

static void print_payload(struct hdr_iterator *meta)
{
	unsigned int i;

	print(meta->tabs, "Payload:");
	print_tabs(meta->tabs + 1);

	/*
	 * Note that this can overflow.
	 * This is just testing code, so don't take it seriously.
	 */
	for (i = 0; i < 5; i++)
		pr_cont("%u ", ((__u8 *)(meta->ptr))     [i]);
	pr_cont("...\n");

	meta->done = true;
}

static void print_hdr_chain(struct hdr_iterator *meta)
{
	while (!meta->done) {
		switch (meta->type) {
		case HP_IPV4:
			print_ipv4_hdr(meta);
			break;

		case HP_IPV6:
			print_ipv6_hdr(meta);
			break;

		case HP_TCP:
			print_tcphdr(meta);
			break;

		case HP_UDP:
			print_udphdr(meta);
			break;

		case HP_ICMP4:
			print_icmp4hdr(meta);
			break;

		case HP_ICMP6:
			print_icmp6hdr(meta);
			break;

		case HP_HOP:
		case HP_ROUTING:
		case HP_DEST:
			print_exthdr(meta);
			break;

		case HP_FRAG:
			print_fraghdr(meta);
			break;

		case HP_PAYLOAD:
			print_payload(meta);
			break;

		default:
			print(meta->tabs, "[Unknown header type: %u]",
					meta->type);
			return;
		}
	}
}

static void print_headers(struct sk_buff *skb, unsigned int tabs)
{
	struct hdr_iterator meta = {
		.tabs = tabs + 1,
		.ptr = skb->data,
		.type = skb->data[0] >> 4,
		.done = false,
	};

	print(tabs, "Content:");
	switch (meta.type) {
	case 4:
		meta.type = HP_IPV4;
		break;
	case 6:
		meta.type = HP_IPV6;
		break;
	default:
		print(tabs + 1, "[Unknown layer 3 protocol: %u]", meta.type);
		return;
	}

	print_hdr_chain(&meta);
}

static void print_shinfo_fields(struct sk_buff *skb, unsigned int tabs)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int f;
	struct sk_buff *iter;

	print(tabs, "shared info:");
	tabs++;

	print(tabs, "nr_frags:%u", shinfo->nr_frags);
	print(tabs, "tx_flags:%u", shinfo->tx_flags);
	print(tabs, "gso_size:%u", shinfo->gso_size);
	print(tabs, "gso_segs:%u", shinfo->gso_segs);
	print(tabs, "gso_type:%u", shinfo->gso_type);

	print(tabs, "frags:");
	tabs++;
	for (f = 0; f < shinfo->nr_frags; f++) {
		print(tabs, "%u page_offset:%u size:%u", f,
				shinfo->frags[f].page_offset,
				shinfo->frags[f].size);
	}
	tabs--;

	skb_walk_frags(skb, iter)
		__skb_log(iter, "frag", tabs);
}

static void __skb_log(struct sk_buff *skb, char *header, unsigned int tabs)
{
	pr_info("=================\n");
	print(tabs, "%s", header);
	tabs++;

	print_skb_fields(skb, tabs);
	print_headers(skb, tabs);
	print_shinfo_fields(skb, tabs);
}

static unsigned int pkts_printed = 0;

/**
 * Assumes that the headers of the packet can be found in the head area.
 * (ie. Do not call before `pkt_init_ipv*()`.)
 */
void skb_log(struct sk_buff *skb, char *label)
{
	if (skb->mark == 5) {
		__skb_log(skb, label, 0);
		return;
	}

	if (pkts_printed > 4)
		return;
	pkts_printed++;
	skb->mark = 5;

	__skb_log(skb, label, 0);
}
