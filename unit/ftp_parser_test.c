#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"

static struct sk_buff *create_skb(unsigned char *payload)
{
	struct sk_buff *skb;
	struct tuple tuple6;
	size_t l3_hdr_len = sizeof(struct ipv6hdr);
	size_t l4_hdr_len = sizeof(struct tcphdr);
	size_t payload_len = strlen(payload);
	size_t datagram_len = l4_hdr_len + payload_len;

	if (init_tuple6(&tuple6, "1::1", 4321, "2::2", 21, L4PROTO_TCP)) {
		log_debug("tuple init failure.");
		return NULL;
	}

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + datagram_len, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb->protocol = htons(ETH_P_IP);
	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, l3_hdr_len + datagram_len);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3_hdr_len);

	if (init_ipv6_hdr(ipv6_hdr(skb), datagram_len, NEXTHDR_TCP, &tuple6,
			true, false, 0, 64)) {
		log_debug("l3 hdr init failure.");
		goto fail;
	}

	if (init_tcp_hdr(tcp_hdr(skb), ETH_P_IPV6, datagram_len, &tuple6)) {
		log_debug("l4 hdr init failure.");
		goto fail;
	}

	memcpy(tcp_hdr(skb) + 1, payload, payload_len);
	return skb;

fail:
	kfree_skb(skb);
	return NULL;
}

static struct ftp_parser *create_parser(unsigned char *skb_payload)
{
	struct sk_buff *skb;
	unsigned int payload_offset;

	skb = create_skb(skb_payload);
	if (!skb)
		return NULL;

	payload_offset = skb_transport_offset(skb) + sizeof(struct tcphdr);
	return parser_create(skb, payload_offset);
}

static void destroy_parser(struct ftp_parser *parser)
{
	kfree_skb(parser->skb);
	parser_destroy(parser);
}

bool test_auth(void)
{
	struct ftp_parser *parser;
	struct ftp_client_msg msg;
	bool success = true;

	/* TODO command codes are case-insensitive. */

	parser = create_parser("AUTH\r\n");
	if (!parser)
		return false;
	success &= ASSERT_INT(0, parser_client_next(parser, &msg), "simple.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "simple.code");
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "simple.end");
	destroy_parser(parser);

	parser = create_parser("AUTH \r\n");
	if (!parser)
		return false;
	success &= ASSERT_INT(0, parser_client_next(parser, &msg), "space.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "space.code");
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "space.end");
	destroy_parser(parser);

	parser = create_parser("AUTH \t     \t  \r \n\r\n");
	if (!parser)
		return false;
	success &= ASSERT_INT(0, parser_client_next(parser, &msg), "whitespace.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "whitespace.code");
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "whitespace.end");
	destroy_parser(parser);

	parser = create_parser("AUTH foo bar\r\n");
	if (!parser)
		return false;
	success &= ASSERT_INT(0, parser_client_next(parser, &msg), "params.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "params.code");
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "params.end");
	destroy_parser(parser);

	parser = create_parser("AUTH");
	if (!parser)
		return false;
	/*
	 * TODO Ok, this is bad.
	 * I hadn't realized I'm supposed to assemble TCP segments. Even the RFC
	 * is telling me, ffs.
	 *
	 * That pretty much trumps the kernelspace approach. Moving the ALG to
	 * userspace now.
	 * Going to commit for backup purposes and redesign this mess.
	 * Hope it works this time...
	 */
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "bad-syntax.result");
	destroy_parser(parser);

	parser = create_parser("AUTH   ");
	if (!parser)
		return false;
	success &= ASSERT_INT(-ENOENT, parser_client_next(parser, &msg), "bad-syntax+whitespace.result");
	destroy_parser(parser);

	return success;
}

int init_module(void)
{
	START_TESTS("FTP parser");

	CALL_TEST(test_auth(), "AUTH parsing test");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("FTP parser module test.");
