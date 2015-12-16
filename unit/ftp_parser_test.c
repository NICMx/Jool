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

static int create_parser(struct ftp_parser *parser, unsigned char *skb_payload)
{
	struct sk_buff *skb;
	unsigned int payload_offset;

	skb = create_skb(skb_payload);
	if (!skb)
		return -ENOMEM;

	payload_offset = skb_transport_offset(skb) + sizeof(struct tcphdr);
	parser_init(parser, skb, payload_offset);

	return 0;
}

static int create_parser_continue(struct ftp_parser *parser,
		unsigned char *skb_payload,
		struct ftp_parser *unfinished_parser)
{
	struct sk_buff *skb;
	unsigned int payload_offset;

	skb = create_skb(skb_payload);
	if (!skb)
		return -ENOMEM;

	payload_offset = skb_transport_offset(skb) + sizeof(struct tcphdr);
	parser_init_continue(parser, skb, payload_offset,
			unfinished_parser->line,
			unfinished_parser->line_len);
	unfinished_parser->line = NULL;
	unfinished_parser->line_len = 0;

	return 0;
}

static void destroy_parser(struct ftp_parser *parser)
{
	kfree_skb(parser->skb);
	parser_destroy(parser);
}

bool test_auth(void)
{
	struct ftp_parser parser;
	struct ftp_parser parser2;
	struct ftp_client_msg msg;
	bool success = true;

	if (create_parser(&parser, "AUTH\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_client_next(&parser, &msg), "simple.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "simple.code");
	success &= ASSERT_INT(EOP, parser_client_next(&parser, &msg), "simple.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "AuTh \r\n"))
		return false;
	success &= ASSERT_INT(0, parser_client_next(&parser, &msg), "space.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "space.code");
	success &= ASSERT_INT(EOP, parser_client_next(&parser, &msg), "space.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "auth \t     \t  \r \n\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_client_next(&parser, &msg), "whitespace.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "whitespace.code");
	success &= ASSERT_INT(EOP, parser_client_next(&parser, &msg), "whitespace.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "autH foo bar\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_client_next(&parser, &msg), "params.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "params.code");
	success &= ASSERT_INT(EOP, parser_client_next(&parser, &msg), "params.end");
	destroy_parser(&parser);

	/* { */

	if (create_parser(&parser, "AUTH"))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_client_next(&parser, &msg), "truncated.result.bad");

	if (create_parser_continue(&parser2, "\r\n", &parser))
		return false;
	success &= ASSERT_INT(0, parser_client_next(&parser2, &msg), "truncated.result.good");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "truncated.code");
	success &= ASSERT_INT(EOP, parser_client_next(&parser2, &msg), "truncated.end");

	destroy_parser(&parser);
	destroy_parser(&parser2);

	/* } */

	if (create_parser(&parser, "AUTH   "))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_client_next(&parser, &msg), "bad-syntax+whitespace.result");
	destroy_parser(&parser);

	return success;
}

int init_module(void)
{
	int error;
	START_TESTS("FTP parser");

	error = ftpparser_module_init();
	if (error)
		return error;

	CALL_TEST(test_auth(), "AUTH parsing test");

	ftpparser_module_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("FTP parser module test.");
