#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"

#define IAC	"\xFF"
#define NOP	"\xF1"
#define WILL	"\xFB"
#define DO	"\xFD"

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

static void destroy_parser(struct ftp_parser *parser)
{
	kfree_skb(parser->skb);
	parser_destroy(parser);
}

static int create_subsequent_parser(struct ftp_parser *parser,
		unsigned char *skb_payload)
{
	struct sk_buff *skb;
	unsigned int payload_offset;

	char *line;
	unsigned int line_len;
	unsigned int unfinished_line_clean;

	line = parser->line;
	line_len = parser->line_len;
	unfinished_line_clean = parser->line_clean;

	parser->line = NULL;
	destroy_parser(parser);

	skb = create_skb(skb_payload);
	if (!skb)
		return -ENOMEM;

	payload_offset = skb_transport_offset(skb) + sizeof(struct tcphdr);
	parser_init_continue(parser, skb, payload_offset, line, line_len,
			unfinished_line_clean);
	return 0;
}

bool test_telnet_lines(void)
{
	struct ftp_parser parser;
	char *line;
	bool success = true;

	if (create_parser(&parser, ""))
		return false;
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "empty.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "simple.result");
	success &= ASSERT_STR("foo\r\n", line, "simple.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "simple.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo bar\r\nfubar\r\n baz qux \r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "multiline.1.result");
	success &= ASSERT_STR("foo bar\r\n", line, "multiline.1.str");
	kfree(line);
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "multiline.2.result");
	success &= ASSERT_STR("fubar\r\n", line, "multiline.2.str");
	kfree(line);
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "multiline.3.result");
	success &= ASSERT_STR(" baz qux \r\n", line, "multiline.3.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "multiline.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo"))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "truncated.1.result");
	if (create_subsequent_parser(&parser, "bar"))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "truncated.2.result");
	if (create_subsequent_parser(&parser, "\r\nbaz\r\nqux"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "truncated.3.result");
	success &= ASSERT_STR("foobar\r\n", line, "truncated.3.str");
	kfree(line);
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "truncated.4.result");
	success &= ASSERT_STR("baz\r\n", line, "truncated.4.str");
	kfree(line);
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "truncated.5.result");
	if (create_subsequent_parser(&parser, "norf\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "truncated.6.result");
	success &= ASSERT_STR("quxnorf\r\n", line, "truncated.6.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "truncated.eop");
	destroy_parser(&parser);

	return success;
}

bool test_telnet_escaped_iac(void)
{
	struct ftp_parser parser;
	char *line;
	bool success = true;

	if (create_parser(&parser, IAC IAC))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "1.alone");
	if (create_subsequent_parser(&parser, "foo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "1.result");
	success &= ASSERT_STR(IAC "foo\r\n", line, "1.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "1.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "f" IAC IAC "oo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "2.result");
	success &= ASSERT_STR("f" IAC "oo\r\n", line, "2.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "2.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC IAC "\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "3.result");
	success &= ASSERT_STR("foo" IAC "\r\n", line, "3.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "3.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo\r" IAC IAC "\n"))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "4.truncated");
	if (create_subsequent_parser(&parser, "\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "4.result");
	success &= ASSERT_STR("foo\r" IAC "\n\r\n", line, "4.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "4.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated1");
	if (create_subsequent_parser(&parser, IAC "bar" IAC IAC))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated2");
	if (create_subsequent_parser(&parser, "norf\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "5.result");
	success &= ASSERT_STR("foo" IAC "bar" IAC "norf\r\n", line, "5.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "5.eop");
	destroy_parser(&parser);

	return success;
}

bool test_telnet_commands(void)
{
	struct ftp_parser parser;
	char *line;
	bool success = true;

	if (create_parser(&parser, IAC NOP))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "1.alone");
	if (create_subsequent_parser(&parser, "foo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "1.result");
	success &= ASSERT_STR("foo\r\n", line, "1.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "1.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "f" IAC NOP "oo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "2.result");
	success &= ASSERT_STR("foo\r\n", line, "2.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "2.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC NOP "\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "3.result");
	success &= ASSERT_STR("foo\r\n", line, "3.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "3.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo\r" IAC NOP "\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "4.result");
	success &= ASSERT_STR("foo\r\n", line, "4.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "4.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated1");
	if (create_subsequent_parser(&parser, NOP "bar" IAC NOP))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated2");
	if (create_subsequent_parser(&parser, "norf\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "5.result");
	success &= ASSERT_STR("foobarnorf\r\n", line, "5.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "5.eop");
	destroy_parser(&parser);

	return success;
}

bool test_telnet_options(void)
{
	struct ftp_parser parser;
	char *line;
	bool success = true;

	if (create_parser(&parser, IAC DO NOP))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "1.alone");
	if (create_subsequent_parser(&parser, "foo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "1.result");
	success &= ASSERT_STR("foo\r\n", line, "1.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "1.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "f" IAC WILL NOP "oo\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "2.result");
	success &= ASSERT_STR("foo\r\n", line, "2.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "2.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC DO NOP "\r\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "3.result");
	success &= ASSERT_STR("foo\r\n", line, "3.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "3.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo\r" IAC WILL NOP "\n"))
		return false;
	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "4.result");
	success &= ASSERT_STR("foo\r\n", line, "4.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "4.eop");
	destroy_parser(&parser);

	if (create_parser(&parser, "foo" IAC))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated1");
	if (create_subsequent_parser(&parser, DO NOP "bar" IAC WILL))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated2");
	if (create_subsequent_parser(&parser, NOP "baz" IAC DO NOP))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, parser_next_line(&parser, &line), "5.truncated2");
	if (create_subsequent_parser(&parser, "norf\r\n"))
		return false;

	success &= ASSERT_INT(0, parser_next_line(&parser, &line), "5.result");
	success &= ASSERT_STR("foobarbaznorf\r\n", line, "5.str");
	kfree(line);
	success &= ASSERT_INT(EOP, parser_next_line(&parser, &line), "5.eop");
	destroy_parser(&parser);

	return success;
}

bool test_ftp_auth(void)
{
	struct ftp_parser parser;
	struct ftp_client_msg msg;
	bool success = true;

	if (create_parser(&parser, "AUTH\r\n"))
		return false;
	success &= ASSERT_INT(0, client_next_token(&parser, &msg), "simple.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "simple.code");
	success &= ASSERT_INT(EOP, client_next_token(&parser, &msg), "simple.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "AuTh \r\n"))
		return false;
	success &= ASSERT_INT(0, client_next_token(&parser, &msg), "space.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "space.code");
	success &= ASSERT_INT(EOP, client_next_token(&parser, &msg), "space.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "auth \t     \t  \r \n\r\n"))
		return false;
	success &= ASSERT_INT(0, client_next_token(&parser, &msg), "whitespace.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "whitespace.code");
	success &= ASSERT_INT(EOP, client_next_token(&parser, &msg), "whitespace.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "autH foo bar\r\n"))
		return false;
	success &= ASSERT_INT(0, client_next_token(&parser, &msg), "params.result");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "params.code");
	success &= ASSERT_INT(EOP, client_next_token(&parser, &msg), "params.end");
	destroy_parser(&parser);

	if (create_parser(&parser, "AUTH"))
		return false;
	success &= ASSERT_INT(-ETRUNCATED, client_next_token(&parser, &msg), "truncated.result.bad");
	if (create_subsequent_parser(&parser, "\r\n"))
		return false;
	success &= ASSERT_INT(0, client_next_token(&parser, &msg), "truncated.result.good");
	success &= ASSERT_INT(msg.code, FTP_AUTH, "truncated.code");
	success &= ASSERT_INT(EOP, client_next_token(&parser, &msg), "truncated.end");
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

	CALL_TEST(test_telnet_lines(), "Telnet simple");
	CALL_TEST(test_telnet_escaped_iac(), "Telnet escaped 255s");
	CALL_TEST(test_telnet_commands(), "Telnet commands");
	CALL_TEST(test_telnet_options(), "Telnet options");

	CALL_TEST(test_ftp_auth(), "AUTH test");
	/* TODO Test the others. */

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
