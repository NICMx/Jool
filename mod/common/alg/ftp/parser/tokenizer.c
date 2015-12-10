#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"

#include <linux/inet.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/alg/ftp/parser/parser.h"

static int parse_auth(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	result->code = FTP_AUTH;
	return 0;
}

static int parse_algs(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	struct ftp_word token;
	int error;

	error = next_word(parser, &token);
	if (error)
		return error;

	if (word_equals(&token, "STATUS64")) {
		result->algs.arg = ALGS_STATUS64;
	} else if (word_equals(&token, "ENABLE64")) {
		result->algs.arg = ALGS_ENABLE64;
	} else if (word_equals(&token, "DISABLE64")) {
		result->algs.arg = ALGS_DISABLE64;
	} else {
		log_debug("Unknown ALGS argument.");
		return -EINVAL;
	}

	result->code = FTP_ALGS;
	return 0;
}

static int parse_eprt(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	/* 4 delimiters, 1 net-prt, 45 net-addr, 5 tcp-port, 1 null chara. */
	/* (ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190 -> 45) */
	char line[4 + 1 + 45 + 5 + 1];
	const char *end_of_addr;
	int error;
	int success;

	result->code = FTP_EPRT;

	error = next_line(parser, line, sizeof(line));
	if (error)
		return error;

	error = kstrtouint(&line[1], 10, &result->eprt.proto);
	if (error) {
		log_debug("Errcode %d parsing EPRT net-prt.", error);
		return error;
	}

	switch (result->eprt.proto) {
	case 1:
		success = in4_pton(&line[3], -1, (u8 *) &result->eprt.addr4.l3,
				line[0], &end_of_addr);
		if (!success) {
			log_debug("EPRTv4 address is bogus.");
			return -EINVAL;
		}
		error = kstrtou16(end_of_addr + 1, 10, &result->eprt.addr4.l4);
		if (error) {
			log_debug("Errcode %d parsing EPRTv4 port.", error);
			return error;
		}
		break;
	case 2:
		success = in6_pton(&line[3], -1, (u8 *) &result->eprt.addr6.l3,
				line[0], &end_of_addr);
		if (!success) {
			log_debug("EPRTv6 address is bogus.");
			return -EINVAL;
		}
		error = kstrtou16(end_of_addr + 1, 10, &result->eprt.addr6.l4);
		if (error) {
			log_debug("Errcode %d parsing EPRTv6 port.", error);
			return error;
		}
		break;
	default:
		/* This prevents net-prt length being > 1, yay. */
		log_debug("Unknown net-prt.");
		error = -EINVAL;
		break;
	}

	return error;
}

static int parse_epsv(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	/* "ALL" + null chara */
	char line[3 + 1];
	int error;

	result->code = FTP_EPSV;

	error = next_line(parser, line, sizeof(line));
	if (error)
		return error;

	if (line_starts_with(line, "ALL")) {
		result->epsv.type = EPSV_ALL;
	} else if (line_starts_with(line, "1")) {
		result->epsv.type = EPSV_CONTAINS_PROTO;
		result->epsv.proto = 1;
	} else if (line_starts_with(line, "2")) {
		result->epsv.type = EPSV_CONTAINS_PROTO;
		result->epsv.proto = 2;
	} else {
		result->epsv.type = EPSV_EMPTY;
	}

	return 0;
}

static int parse_client_unrecognized(struct ftp_client_msg *result)
{
	result->code = FTP_CLIENT_UNRECOGNIZED;
	return 0;
}

int parser_client_next(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	struct ftp_word token;
	int error;

	error = next_word(parser, &token);
	if (error)
		return error;

	if (word_equals(&token, "AUTH")) {
		error = parse_auth(parser, result);
	} else if (word_equals(&token, "ALGS")) {
		error = parse_algs(parser, result);
	} else if (word_equals(&token, "EPRT")) {
		error = parse_eprt(parser, result);
	} else if (word_equals(&token, "EPSV")) {
		error = parse_epsv(parser, result);
	} else {
		error = parse_client_unrecognized(result);
	}

	return error ? error : waste_line(parser);
}

static int parse_227(struct ftp_parser *parser, struct ftp_server_msg *result)
{
	union {
		u8 as8[4];
		u16 as16[2];
		u32 as32;
	} tmp;
	unsigned int i;
	int error;

	result->code = FTP_227;

	error = waste_until(parser, '(');
	if (error)
		return error;

	for (i = 0; i < 4; i++) {
		error = next_u8(parser, &tmp.as8[i]);
		if (error)
			return error;
	}
	result->epsv_227.addr.l3.s_addr = cpu_to_be32(tmp.as32);

	for (i = 0; i < 2; i++) {
		error = next_u8(parser, &tmp.as8[i]);
		if (error)
			return error;
	}
	result->epsv_227.addr.l4 = cpu_to_be16(tmp.as16[0]);

	return 0;
}

static int parse_error(struct ftp_parser *parser, struct ftp_server_msg *result)
{
	result->code = FTP_REJECT;
	return 0;
}

static int parse_server_unrecognized(struct ftp_server_msg *result)
{
	result->code = FTP_SERVER_UNRECOGNIZED;
	return 0;
}

int parser_server_next(struct ftp_parser *parser, struct ftp_server_msg *result)
{
	struct ftp_word token;
	int error;

	error = next_word(parser, &token);
	if (error)
		return error;

	if (word_equals(&token, "227")) {
		error = parse_227(parser, result);
	} else if (word_equals(&token, "4")) {
		error = parse_error(parser, result);
	} else if (word_equals(&token, "5")) {
		error = parse_error(parser, result);
	} else {
		error = parse_server_unrecognized(result);
	}

	return error;
}
