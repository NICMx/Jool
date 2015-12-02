#include "nat64/mod/common/alg/ftp/parser.h"

#define CR	0x0d
#define LF	0x0a
#define WILL	251
#define DO	253
#define IAC	255

struct telnet_opt {
	unsigned char code;
	struct list_head hook;
};

struct ftp_ctrl_channel_parser *ftpparser_create(struct sk_buff *skb)
{
	struct ftp_ctrl_channel_parser *parser;

	parser = kmalloc(sizeof(*parser), GFP_ATOMIC);
	if (!parser)
		return NULL;

	parser->skb = skb;
	INIT_LIST_HEAD(&parser->options);
	parser->skb_offset = 0;
	parser->buffer_offset = 0;

	return NULL;
}

static int fetch_next_block(struct ftp_ctrl_channel_parser *parser)
{
	int error;

	if (parser->skb_offset > parser->skb->len)
		return -ENOENT;

	log_debug("Fetching packet bytes.");

	error = skb_copy_bits(parser->skb, parser->skb_offset, parser->buffer,
			sizeof(parser->buffer));
	if (error)
		return error;

	parser->skb_offset += sizeof(parser->buffer);
	parser->buffer_offset = 0;
	return 0;
}

static int fetch_next_chara(struct ftp_ctrl_channel_parser *parser,
		unsigned char *result)
{
	int error;

	if (!parser->skb_offset || parser->buffer_offset >= sizeof(parser->buffer)) {
		error = fetch_next_block(parser);
		if (error)
			return error;
	}

	*result = parser->buffer[parser->buffer_offset];
	parser->buffer_offset++;
	return 0;
}

int handle_iac(struct ftp_ctrl_channel_parser *parser)
{
	struct telnet_opt *opt;
	unsigned char next_chara;
	int error;

	error = fetch_next_chara(parser, &next_chara);
	if (error)
		return error;

	switch (next_chara) {
	case WILL:
	case DO:
		opt = kmalloc(sizeof(*opt), GTP_ATOMIC);
		if (!opt)
			return -ENOMEM;
		opt->code = next_chara;
		list_add_tail(&opt->hook, &parser->options);
		break;
	case IAC:
		break;
	}

	return 0;
}

int ftpparser_server_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_server_msg *token)
{
	unsigned char next_chara;
	int error;

	/*
	 * Parse the next line (until CR LF), fill in @token with its contents.
	 *
	 * Also register any Telnet options in parser->options, so they can be
	 * rejected later.
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
	 *
	 * Return -ENOENT if there are no more lines.
	 */

	do {
		error = fetch_next_chara(parser, &next_chara);
		if (error)
			return error;

		switch (next_chara) {
		case CR: /* Going to look for CRLF. */
			error = fetch_next_chara(parser, &next_chara);
			if (error)
				return error;
			if (next_chara == LF)
				return 0;
			/* TODO going to need backspace. */
			break;
		case '2': /* Going to look for 227. */
		case '4': /* Going to look for 4xx. */
		case '5': /* Going to look for 5xx. */
		case IAC:
			error = handle_iac(parser);
			break;
		}

		if (error)
			return error;
	} while (true);

	WARN(true, "Unreachable code!");
	return -EINVAL;
}

int ftpparser_client_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_client_msg *token)
{
	unsigned char next_chara;
	int error;

	do {
		error = fetch_next_chara(parser, &next_chara);
		if (error)
			return error;

		switch (next_chara) {
		case CR:
			error = fetch_next_chara(parser, &next_chara);
			if (error)
				return error;
			if (next_chara == LF)
				return 0;
			/* TODO going to need backspace. */
			break;
		case 'A': /* Going to look for AUTH or ALGS. */
		case 'E': /* Going to look for EPRT or EPSV. */
		case IAC:
			error = handle_iac(parser);
			break;
		}

		if (error)
			return error;
	} while (true);

	WARN(true, "Unreachable code!");
	return -EINVAL;
}

void ftpparser_destroy(struct ftp_ctrl_channel_parser *parser)
{
	struct telnet_opt *opt;

	/*
	 * Reject parser->options in a separate packet (and delete the list),
	 * resize the packet (skb->stuff and headers).
	 */

	while (!list_empty(parser->options)) {
		opt = list_first_entry(&parser->options, typeof(*opt), hook);
		list_del(&opt->hook);
		kfree(opt);
	}
	kfree(parser);
}
