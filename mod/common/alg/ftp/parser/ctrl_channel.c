#include "nat64/mod/common/alg/ftp/parser/ctrl_channel.h"
#include "nat64/mod/common/types.h"

int ftpparser_init(struct ftp_ctrl_channel_parser *parser, struct packet *pkt)
{
	parser->pkt = pkt;
	parser->current_chunk = NULL;
	return telnet_parse(pkt->skb, pkt_payload_offset(pkt), &parser->chunks);
}

static int advance_chunk(struct ftp_ctrl_channel_parser *parser)
{
	struct list_head *next;

	next = parser->current_chunk
			? parser->current_chunk->list_hook.next
			: parser->chunks.next;

	if (next == &parser->chunks)
		return -ENOENT;

	parser->current_chunk = telnet_chunk_entry(next);
	return 0;
}

static bool chunk_starts_with(struct telnet_chunk *chunk, char *prefix)
{
	return strncmp(chunk->prefix, prefix, strlen(prefix)) == 0;
}

static int tokenize_227(struct telnet_chunk *chunk,
		struct ftp_server_msg *token)
{
	token->code = FTP_227;
	/* TODO */
	token->epsv_227.addr.l3.s_addr = cpu_to_be32(0xc0000201);
	token->epsv_227.addr.l4 = 1234;
	return 0;
}

static int tokenize_error(struct telnet_chunk *chunk,
		struct ftp_server_msg *token)
{
	token->code = FTP_REJECT;
	return 0;
}

static int tokenize_server_unrecognized(struct ftp_server_msg *token)
{
	token->code = FTP_SERVER_UNRECOGNIZED;
	return 0;
}

int ftpparser_server_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_server_msg *token)
{
	struct telnet_chunk *chunk;
	int error;

	/*
	 * Parse the next line (until CR LF), fill in @token with its contents.
	 *
	 * Return -ENOENT if there are no more lines.
	 */

	do {
		error = advance_chunk(parser);
		if (error)
			return error;
	} while (parser->current_chunk->type != TELNET_TEXT);

	chunk = parser->current_chunk;
	if (chunk_starts_with(chunk, "227")) {
		error = tokenize_227(chunk, token);
	} else if (chunk_starts_with(chunk, "4")) {
		error = tokenize_error(chunk, token);
	} else if (chunk_starts_with(chunk, "5")) {
		error = tokenize_error(chunk, token);
	} else {
		error = tokenize_server_unrecognized(token);
	}

	return error;
}

static int tokenize_auth(struct telnet_chunk *chunk,
		struct ftp_client_msg *token)
{
	token->code = FTP_AUTH;
	return 0;
}

static int tokenize_algs(struct telnet_chunk *chunk,
		struct ftp_client_msg *token)
{
	token->code = FTP_ALGS;
	/* TODO */
	token->algs.arg = ALGS_ENABLE64;
	return 0;
}

static int tokenize_eprt(struct telnet_chunk *chunk,
		struct ftp_client_msg *token)
{
	token->code = FTP_EPRT;
	/* TODO */
	token->eprt.proto = 1;
	token->eprt.addr4.l3.s_addr = cpu_to_be32(0xc0000201);
	token->eprt.addr4.l4 = 1234;
	/* token->eprt.addr6.l3.s_addr = ; */
	/* token->eprt.addr6.l4 = ; */
	return 0;
}

static int tokenize_epsv(struct telnet_chunk *chunk,
		struct ftp_client_msg *token)
{
	token->code = FTP_EPSV;
	/* TODO */
	token->epsv.proto = 1;
	token->epsv.type = EPSV_EMPTY;
	return 0;
}

static int tokenize_client_unrecognized(struct ftp_client_msg *token)
{
	token->code = FTP_CLIENT_UNRECOGNIZED;
	return 0;
}

int ftpparser_client_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_client_msg *token)
{
	struct telnet_chunk *chunk;
	int error;

	do {
		error = advance_chunk(parser);
		if (error)
			return error;
	} while (parser->current_chunk->type != TELNET_TEXT);

	chunk = parser->current_chunk;
	if (chunk_starts_with(chunk, "AUTH")) {
		error = tokenize_auth(chunk, token);
	} else if (chunk_starts_with(chunk, "ALGS")) {
		error = tokenize_algs(chunk, token);
	} else if (chunk_starts_with(chunk, "EPRT")) {
		error = tokenize_eprt(chunk, token);
	} else if (chunk_starts_with(chunk, "EPSV")) {
		error = tokenize_epsv(chunk, token);
	} else {
		error = tokenize_client_unrecognized(token);
	}

	return error;
}

void ftpparser_destroy(struct ftp_ctrl_channel_parser *parser)
{
	/*
	 * Before you destroy the chunk list, reject the options in a separate
	 * packet.
	 *
	 * BTW:
	 *
	 *  Telnet option negotiation attempts by either the
	 *  client or the server, except for those allowed by [RFC1123], MUST be
	 *  refused by the FTP ALG without relaying those attempts.  For the
	 *  purpose of Telnet option negotiation, an FTP ALG MUST follow the
	 *  behavior of an FTP server as specified in [RFC1123], Section
	 *  4.1.2.12.
	 *
	 * It seems to be saying the same thing twice: Ban all options. ALL
	 * options. RFC1123 doesn't define any exceptions.
	 * (RFC 1123 "exceptions" are SYNCH and IP, both of which are actually
	 * commands, not options...)
	 */
	/* Also resize the packet (skb->stuff and headers). */
}
