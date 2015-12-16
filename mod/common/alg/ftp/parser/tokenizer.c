#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"
#include <linux/inet.h>
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/alg/ftp/parser/parser.h"

static int parse_auth(struct ftp_parser *parser, struct ftp_client_msg *result)
{
	result->code = FTP_AUTH;
	return 0;
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

static int parse_algs(char *line, struct ftp_client_msg *result)
{
	result->code = FTP_ALGS;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "ALGS ". */
	if (!line)
		return -ENOENT;

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

static int parse_eprt(char *line, struct ftp_client_msg *result)
{
	char delimiter[2];
	char *delimiter1;
	char *delimiter2;
	char *delimiter3;
	int error;
	int success;

	result->code = FTP_EPRT;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "ALGS ". */
	if (!line)
		return -ENOENT;

	delimiter[0] = line[0];
	delimiter[1] = '\0';

	delimiter1 = strstr(line, delimiter);
	if (!line)
		return -ENOENT; /* TODO */
	delimiter2 = strstr(delimiter1 + 1, delimiter);
	if (!delimiter2)
		return -ENOENT;
	delimiter3 = strstr(delimiter2 + 1, delimiter);
	if (!delimiter3)
		return -ENOENT;

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

static int parse_epsv(char *line, struct ftp_client_msg *result)
{
	result->code = FTP_EPSV;

	line = skip_whitespace(line + 5); /* "+ 5" = Skip "EPSV ". */
	if (!line)
		return -ENOENT;

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
	char *line;
	int error;

	error = next_line(parser, &line);
	if (error)
		return error;

	if (line_starts_with(line, "AUTH")) {
		error = parse_auth(parser, result);
	} else if (line_starts_with(line, "ALGS")) {
		error = parse_algs(line, result);
	} else if (line_starts_with(line, "EPRT")) {
		error = parse_eprt(line, result);
	} else if (line_starts_with(line, "EPSV")) {
		error = parse_epsv(line, result);
	} else {
		error = parse_client_unrecognized(result);
	}

	kfree(line);
	return error;
}

static int parse_227(char *line, struct ftp_server_msg *result)
{
	union {
		u8 as8[4];
		u16 as16[2];
		u32 as32;
	} tmp;
	unsigned int i;
	int error;

	result->code = FTP_227;

	line = strstr(line, "(");
	if (!line)
		return -ENOENT; /* TODO */
	line++;

	for (i = 0; i < 4; i++) {
		error = kstrtou8(line, 10, &tmp.as8[i]);
		if (error)
			return error;
		line = strstr(line, ",");
		if (!line)
			return -ENOENT;
		line++;
	}
	result->epsv_227.addr.l3.s_addr = cpu_to_be32(tmp.as32);

	for (i = 0; i < 2; i++) {
		error = kstrtou8(line, 10, &tmp.as8[i]);
		if (error)
			return error;
		line = strstr(line, ",");
		if (!line)
			return -ENOENT;
		line++;
	}
	result->epsv_227.addr.l4 = cpu_to_be16(tmp.as16[0]);

	return 0;
}

static int parse_error(struct ftp_server_msg *result)
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
	char *line;
	int error;

	error = next_line(parser, &line);
	if (error)
		return error;

	if (line_starts_with(line, "227")) {
		error = parse_227(line, result);
	} else if (line_starts_with(line, "4")) {
		error = parse_error(result);
	} else if (line_starts_with(line, "5")) {
		error = parse_error(result);
	} else {
		error = parse_server_unrecognized(result);
	}

	kfree(line);
	return error;
}
