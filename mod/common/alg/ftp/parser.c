#include "nat64/mod/common/alg/ftp/parser.h"

int ftpparser_init(struct ftp_control_channel_parser *parser,
		struct sk_buff *skb)
{
	parser->skb = skb;
	INIT_LIST_HEAD(&parser->options);
	return 0;
}

int ftpparser_next(struct ftp_parser *parser, char *line)
{
	/*
	 * Read the next line (until CR LF), copy at most 128 charas into @line
	 * (we sholdn't need more). @line is going to be a preallocated char
	 * buffer.
	 *
	 * TODO Is a constant (128) naive?
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
	 * ("exceptions" listed by RFC 1123 are SYNCH and IP, both of which are
	 * actually commands, not options...)
	 *
	 * Return -ENOENT if there are no more lines.
	 */

	return 0;
}

void ftpparser_destroy(struct ftp_control_channel_parser *parser)
{
	/*
	 * Reject parser->options in a separate packet (and delete the list),
	 * resize the packet (skb->stuff and headers).
	 */
}
