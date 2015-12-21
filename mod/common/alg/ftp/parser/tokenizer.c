#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"
#include <linux/inet.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/alg/ftp/parser/parser.h"

static bool is_digit(char chara)
{
	return '0' <= chara && chara <= '9';
}

static bool is_whitespace(char chara)
{
	return chara == ' ' || chara == '\t' || chara == '\r' || chara == '\n';
}

static char *skip_whitespace(char *line)
{
	for (; line[0] != '\0'; line++) {
		if (!is_whitespace(line[0]))
			return line;
	}

	return NULL;
}

static int tokenize_auth(struct ftp_client_msg *result)
{
	result->code = FTP_AUTH;
	return 0;
}

static int tokenize_algs(char *line, struct ftp_client_msg *result)
{
	result->code = FTP_ALGS;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "ALGS ". */
	if (!line) {
		log_debug("ALGS lacks an argument.");
		return -ENOENT;
	}

	if (line_starts_with(line, "STATUS64")) {
		result->algs.arg = ALGS_STATUS64;
	} else if (line_starts_with(line, "ENABLE64")) {
		result->algs.arg = ALGS_ENABLE64;
	} else if (line_starts_with(line, "DISABLE64")) {
		result->algs.arg = ALGS_DISABLE64;
	} else {
		log_debug("Unknown ALGS argument.");
		return -EINVAL;
	}

	return 0;
}

static int tokenize_eprt(char *line, struct ftp_client_msg *result)
{
	char delimiter[2];
	char *delimiter1;
	char *delimiter2;
	char *delimiter3;
	int error;
	int success;

	result->code = FTP_EPRT;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "EPRT ". */
	if (!line) {
		log_debug("EPRT lacks arguments.");
		return -ENOENT;
	}

	delimiter[0] = line[0];
	delimiter[1] = '\0';

	delimiter1 = line;
	delimiter2 = strstr(delimiter1 + 1, delimiter);
	if (!delimiter2) {
		log_debug("EPRT lacks net-addr.");
		return -ENOENT;
	}
	delimiter3 = strstr(delimiter2 + 1, delimiter);
	if (!delimiter3) {
		log_debug("EPRT lacks tcp-port.");
		return -ENOENT;
	}

	error = kstrtouint(delimiter1 + 1, 10, &result->eprt.proto);
	if (error) {
		log_debug("Errcode %d parsing EPRT net-prt.", error);
		return error;
	}

	switch (result->eprt.proto) {
	case 1:
		success = in4_pton(delimiter2 + 1, delimiter3 - delimiter2,
				(u8 *)&result->eprt.addr4.l3,
				delimiter[0], NULL);
		if (!success) {
			log_debug("EPRTv4 address is bogus.");
			return -EINVAL;
		}
		error = kstrtou16(delimiter3 + 1, 10, &result->eprt.addr4.l4);
		if (error) {
			log_debug("Errcode %d parsing EPRTv4 port.", error);
			return error;
		}
		break;
	case 2:
		success = in6_pton(delimiter2 + 1, delimiter3 - delimiter2,
				(u8 *)&result->eprt.addr6.l3,
				delimiter[0], NULL);
		if (!success) {
			log_debug("EPRTv6 address is bogus.");
			return -EINVAL;
		}
		error = kstrtou16(delimiter3 + 1, 10, &result->eprt.addr6.l4);
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

static int tokenize_epsv(char *line, struct ftp_client_msg *result)
{
	result->code = FTP_EPSV;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "EPSV ". */
	if (!line) {
		log_debug("EPSV lacks arguments.");
		return -ENOENT;
	}

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

static int tokenize_client_unrecognized(struct ftp_client_msg *result)
{
	result->code = FTP_CLIENT_UNRECOGNIZED;
	return 0;
}

int client_next_token(struct ftp_parser *parser, struct ftp_client_msg *token)
{
	unsigned int start = parser->line_next_offset;
	char *line;
	int error;

	error = parser_next_line(parser, &line);
	if (error)
		return error;

	token->skb = parser->skb;
	token->start = start;
	token->end = parser->line_next_offset;

	if (line_starts_with(line, "AUTH")) {
		error = tokenize_auth(token);
	} else if (line_starts_with(line, "ALGS")) {
		error = tokenize_algs(line, token);
	} else if (line_starts_with(line, "EPRT")) {
		error = tokenize_eprt(line, token);
	} else if (line_starts_with(line, "EPSV")) {
		error = tokenize_epsv(line, token);
	} else {
		error = tokenize_client_unrecognized(token);
	}

	kfree(line);
	return error;
}

static int tokenize_227(char *line, struct ftp_server_msg *result)
{
	unsigned int nums[6];
	unsigned int i;
	int error;

	result->code = FTP_227;

	for (i = 0; line[i] != '\0'; i++) {
		if (!is_digit(line[i]))
			continue;

		error = sscanf(&line[i], "%u,%u,%u,%u,%u,%u",
				&nums[0], &nums[1], &nums[2],
				&nums[3], &nums[4], &nums[5]);
		if (!error) {
			result->epsv_227.addr.l3.s_addr = cpu_to_be32(
					(nums[0] << 24) | (nums[1] << 16)
					| (nums[2] << 8) | (nums[3]));
			result->epsv_227.addr.l4 = (nums[4] << 8) + nums[5];
			return 0;
		}
	}

	log_debug("227 doesn't have a comma-separated list of 6 numbers.");
	return -EINVAL;
}

static int tokenize_error(struct ftp_server_msg *result)
{
	result->code = FTP_REJECT;
	return 0;
}

static int tokenize_server_unrecognized(struct ftp_server_msg *result)
{
	result->code = FTP_SERVER_UNRECOGNIZED;
	return 0;
}

int server_next_token(struct ftp_parser *parser, struct ftp_server_msg *token)
{
	unsigned int start = parser->line_next_offset;
	char *line;
	int error;

	error = parser_next_line(parser, &line);
	if (error)
		return error;

	token->skb = parser->skb;
	token->start = start;
	token->end = parser->line_next_offset;

	if (line_starts_with(line, "227")) {
		error = tokenize_227(line, token);
	} else if (line_starts_with(line, "4")) {
		error = tokenize_error(token);
	} else if (line_starts_with(line, "5")) {
		error = tokenize_error(token);
	} else {
		error = tokenize_server_unrecognized(token);
	}

	kfree(line);
	return error;
}
