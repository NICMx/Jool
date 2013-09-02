#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "translate_packet.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Translating the Packet module test.");


#define PAYLOAD_LEN 100
static struct in6_addr dummies6[2];
static struct in_addr dummies4[2];


static struct fragment *create_fragment_ipv4(int payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16), u16 df, u16 mf, u16 frag_off)
{
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	struct iphdr *hdr4;
	enum verdict result;

	// init the skb.
	pair4.remote.address = dummies4[0];
	pair4.remote.l4_id = 5644;
	pair4.local.address = dummies4[1];
	pair4.local.l4_id = 6721;
	if (skb_create_fn(&pair4, &skb, payload_len) != 0)
		return NULL;

	hdr4 = ip_hdr(skb);
	hdr4->frag_off = cpu_to_be16(df | mf | frag_off);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	// init the fragment.
	result = frag_create_ipv4(skb, &frag);
	if (!result) {
		log_warning("Could not allocate the fragment.");
		kfree_skb(skb);
		return NULL;
	}

	return frag;
}

static struct packet *create_pkt_ipv4(int payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16))
{
	struct fragment *frag;
	struct packet *pkt;

	frag = create_fragment_ipv4(payload_len, skb_create_fn, IP_DF, 0, 0);
	if (!frag)
		return NULL;

	pkt = pkt_create_ipv4(frag);
	if (!pkt)
		frag_kfree(frag);

	return pkt;
}

static struct fragment *create_fragment_ipv6(int payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16), u16 df, u16 mf, u16 frag_off)
{
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	enum verdict result;

	// init the skb.
	pair6.remote.address = dummies6[0];
	pair6.remote.l4_id = 5644;
	pair6.local.address = dummies6[1];
	pair6.local.l4_id = 6721;
	if (skb_create_fn(&pair6, &skb, payload_len) != 0)
		return NULL;

	hdr6 = ipv6_hdr(skb);
	if (hdr6->nexthdr == NEXTHDR_FRAGMENT) {
		frag_header = (struct frag_hdr *) (hdr6 + 1);
		frag_header->frag_off = cpu_to_be16(frag_off << 3 | mf);
	}

	// init the fragment.
	result = frag_create_ipv6(skb, &frag);
	if (!result) {
		log_warning("Could not allocate the fragment.");
		kfree_skb(skb);
		return NULL;
	}

	return frag;
}

static struct packet *create_pkt_ipv6(int payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16))
{
	struct fragment *frag;
	struct packet *pkt;

	frag = create_fragment_ipv6(payload_len, skb_create_fn, IP_DF, 0, 0);
	if (!frag)
		return NULL;

	pkt = pkt_create_ipv6(frag);
	if (!pkt)
		frag_kfree(frag);

	return pkt;
}

static bool create_tuple_ipv6(struct tuple *tuple, u_int8_t l4proto)
{
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4proto;
	tuple->src.addr.ipv6 = dummies6[0];
	tuple->src.l4_id = 1234;
	tuple->dst.addr.ipv6 = dummies6[1];
	tuple->dst.l4_id = 4321;

	return true;
}

static bool create_tuple_ipv4(struct tuple *tuple, u_int8_t l4proto)
{
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4proto;
	tuple->src.addr.ipv4 = dummies4[0];
	tuple->src.l4_id = 1234;
	tuple->dst.addr.ipv4 = dummies4[1];
	tuple->dst.l4_id = 4321;

	return true;
}

static bool validate_pkt_ipv6_udp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_UDP, tuple))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), payload_len, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_ipv6_tcp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), sizeof(struct tcphdr), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_ipv6_icmp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_icmp6(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_ICMP, tuple))
		return false;
	if (!validate_icmp6_hdr(frag_get_icmp6_hdr(frag), 5644, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_ipv4_udp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len, IPPROTO_UDP, tuple))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), payload_len, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_ipv4_tcp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len, IPPROTO_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), sizeof(struct tcphdr), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_ipv4_icmp(struct packet *pkt, struct tuple *tuple, int payload_len)
{
	struct fragment *frag;

	// Validate the fragment
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_icmp4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	// Validate the skb
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len, IPPROTO_ICMP, tuple))
		return false;
	if (!validate_icmp4_hdr(frag_get_icmp4_hdr(frag), 5644, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool validate_pkt_multiple_4to6(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 3))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 1280 - sizeof(struct ipv6hdr) - sizeof(struct frag_hdr) - sizeof(struct udphdr);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), 1280 - sizeof(struct ipv6hdr), NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, IP6_MF))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), 2000, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = 1232;
	payload_len = 776;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), sizeof(struct frag_hdr) + payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, IP6_MF))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset - sizeof(struct udphdr)))
		return false;

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = 2008;
	payload_len = 100;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the third skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), sizeof(struct frag_hdr) + payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, 0))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}



static bool validate_pkt_multiple_6to4(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 2))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 2000;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag), sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len, IPPROTO_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), sizeof(struct tcphdr), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = sizeof(struct tcphdr) + 2000;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag), sizeof(struct iphdr) + payload_len, IPPROTO_TCP, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}



static bool test_simple_4to6_udp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		return false;
	pkt_in = create_pkt_ipv4(PAYLOAD_LEN, create_skb_ipv4_udp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv6_udp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_simple_4to6_tcp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_TCP))
		return false;
	pkt_in = create_pkt_ipv4(PAYLOAD_LEN, create_skb_ipv4_tcp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv6_tcp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_simple_4to6_icmp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv4(PAYLOAD_LEN, create_skb_ipv4_icmp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv6_icmp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_simple_6to4_udp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_UDP))
		return false;

	pkt_in = create_pkt_ipv6(PAYLOAD_LEN, create_skb_ipv6_udp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv4_udp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_simple_6to4_tcp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_TCP))
		return false;
	pkt_in = create_pkt_ipv6(PAYLOAD_LEN, create_skb_ipv6_tcp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv4_tcp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_simple_6to4_icmp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv6(PAYLOAD_LEN, create_skb_ipv6_icmp);
	if (!pkt_in)
		return false;

	// Call the function
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_ipv4_icmp(&pkt_out, &tuple, PAYLOAD_LEN))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_multiple_4to6_udp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		return false;



	INIT_LIST_HEAD(&pkt_in.fragments);

	frag = create_fragment_ipv4(2000, create_skb_ipv4_udp, 0, IP_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv4(100, create_skb_ipv4_empty, 0, 0, 2008);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	// Call the function
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_multiple_4to6(&pkt_out, &tuple))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool test_multiple_6to4_tcp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	// Init
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_TCP))
		return false;



	INIT_LIST_HEAD(&pkt_in.fragments);

	frag = create_fragment_ipv6(2000, create_skb_ipv6_tcp, 0, IP_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv6(100, create_skb_ipv6_empty, 0, 0, 2008);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	// Call the function
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	// Validate
	if (!validate_pkt_multiple_6to4(&pkt_out, &tuple))
		goto fail;

	// Yaaaaaaaaay
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static void print_skb(struct sk_buff *skb, unsigned char *name, bool is_ipv6)
{
int i;
int offset = (is_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
int len = skb->len - offset;

log_debug("------------------------");
log_debug("%s", name);
log_debug("Length: %d", len);

for (i = 0; i < len; i++) {
	printk("%x ", skb->data[offset + i]);
}
printk("\n");
log_debug("------------------------");
}

static bool test_post_tcp_csum_6to4(void)
{
	struct sk_buff *skb_in = NULL, *skb_out = NULL;
	struct fragment *frag_in = NULL, *frag_out = NULL;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;

	struct tcphdr *hdr_tcp;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (create_skb_ipv6_tcp(&pair6, &skb_in, 100) != 0)
		goto error;
	if (create_skb_ipv4_tcp(&pair4, &skb_out, 100) != 0)
		goto error;

	if (frag_create_ipv6(skb_in, &frag_in) != VER_CONTINUE)
		goto error;
	if (frag_create_ipv4(skb_out, &frag_out) != VER_CONTINUE)
		goto error;

	hdr_tcp = frag_get_tcp_hdr(frag_out);
	expected_csum = hdr_tcp->check;

	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	post_tcp_ipv4(&tuple, frag_in, frag_out);

	return assert_equals_csum(expected_csum, hdr_tcp->check, "Checksum");

error:
	log_debug("errorrrrrrrrrrrrrr1");
	if (frag_in)
		frag_kfree(frag_in);
	else
		kfree_skb(skb_in);
	if (frag_out)
		frag_kfree(frag_out);
	else
		kfree_skb(skb_out);
	return false;
}

static bool test_post_udp_csum_6to4(void)
{
	struct sk_buff *skb_in = NULL, *skb_out = NULL;
	struct fragment *frag_in = NULL, *frag_out = NULL;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;

	struct udphdr *hdr_udp;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (create_skb_ipv6_udp(&pair6, &skb_in, 100) != 0)
		goto error;
	if (create_skb_ipv4_udp(&pair4, &skb_out, 100) != 0)
		goto error;

	if (frag_create_ipv6(skb_in, &frag_in) != VER_CONTINUE)
		goto error;
	if (frag_create_ipv4(skb_out, &frag_out) != VER_CONTINUE)
		goto error;

	hdr_udp = frag_get_udp_hdr(frag_out);
	expected_csum = hdr_udp->check;

	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	post_udp_ipv4(&tuple, frag_in, frag_out);

	return assert_equals_csum(expected_csum, hdr_udp->check, "Checksum");

error:
	log_debug("errorrrrrrrrrrrrrr2");
	if (frag_in)
		frag_kfree(frag_in);
	else
		kfree_skb(skb_in);
	if (frag_out)
		frag_kfree(frag_out);
	else
		kfree_skb(skb_out);
	return false;
}

static bool test_update_csum_4to6(void)
{
	unsigned char in_pkt[256];
	unsigned char out_pkt[256];

	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct tcphdr *hdr_tcp4;
	struct tcphdr *hdr_tcp6;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;

	int datagram_len = sizeof(*hdr_tcp4) + 100;
	__sum16 expected_csum, actual_csum;

	if (init_pair4(&pair4, "1.2.3.4", 5678, "9.10.11.12", 1314) != 0)
		return false;
	if (init_pair6(&pair6, "15::16", 1718, "19::20", 2122) != 0)
		return false;

	hdr4 = (struct iphdr *) &in_pkt[0];
	hdr_tcp4 = (struct tcphdr *) (hdr4 + 1);
	if (init_ipv4_hdr(hdr4, datagram_len, IPPROTO_TCP, &pair4) != 0)
		return false;
	if (init_tcp_hdr(hdr_tcp4, ETH_P_IP, datagram_len, &pair4) != 0)
		return false;
	if (init_payload_normal(hdr_tcp4 + 1, 100) != 0)
		return false;
	if (ipv4_tcp_post(hdr_tcp4, datagram_len, &pair4) != 0)
		return false;

	hdr6 = (struct ipv6hdr *) &out_pkt[0];
	hdr_tcp6 = (struct tcphdr *) (hdr6 + 1);
	if (init_ipv6_hdr(hdr6, datagram_len, NEXTHDR_TCP, &pair6) != 0)
		return false;
	if (init_tcp_hdr(hdr_tcp6, ETH_P_IPV6, datagram_len, &pair6) != 0)
		return false;
	if (init_payload_normal(hdr_tcp6 + 1, 100) != 0)
		return false;
	if (ipv6_tcp_post(hdr_tcp6, datagram_len, &pair6) != 0)
		return false;

	expected_csum = hdr_tcp6->check;
	actual_csum = update_csum_4to6(hdr_tcp4->check,
			hdr4, cpu_to_be16(5678), cpu_to_be16(1314),
			hdr6, cpu_to_be16(1718), cpu_to_be16(2122));

	return assert_equals_csum(expected_csum, actual_csum, "Checksums");
}

int init_module(void)
{
	START_TESTS("Translating the Packet (IPv4 to IPv6)");

	if (str_to_addr6("1::1", &dummies6[0]) != 0)
		return -EINVAL;
	if (str_to_addr6("2::2", &dummies6[1]) != 0)
		return -EINVAL;
	if (str_to_addr4("1.1.1.1", &dummies4[0]) != 0)
		return -EINVAL;
	if (str_to_addr4("2.2.2.2", &dummies4[1]) != 0)
		return -EINVAL;

	translate_packet_init();

	CALL_TEST(test_post_tcp_csum_6to4(), "Recomputed TCP checksum 6->4");
	CALL_TEST(test_post_udp_csum_6to4(), "Recomputed UDP checksum 6->4");
	CALL_TEST(test_update_csum_4to6(), "Recomputed checksum 4->6");

	CALL_TEST(test_simple_4to6_udp(), "Simple 4->6 UDP");
	CALL_TEST(test_simple_4to6_tcp(), "Simple 4->6 TCP");
	CALL_TEST(test_simple_4to6_icmp(), "Simple 4->6 ICMP");
	CALL_TEST(test_simple_6to4_udp(), "Simple 6->4 UDP");
	CALL_TEST(test_simple_6to4_tcp(), "Simple 6->4 TCP");
	CALL_TEST(test_simple_6to4_icmp(), "Simple 6->4 ICMP");
	CALL_TEST(test_multiple_4to6_udp(), "Multiple 4->6 UDP");
	CALL_TEST(test_multiple_6to4_tcp(), "Multiple 6->4 TCP");

	translate_packet_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
