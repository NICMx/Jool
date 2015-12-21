#include "nat64/mod/common/alg/ftp/parser/parser.h"
#include "nat64/mod/common/types.h"

#define WILL	251
#define DO	253
#define IAC	255
#define	LF	"\n"

static struct ts_config *ts_config;

int ftpparser_module_init(void)
{
	ts_config = textsearch_prepare("kmp", LF, strlen(LF), GFP_KERNEL,
			TS_AUTOLOAD);
	return IS_ERR(ts_config) ? PTR_ERR(ts_config) : 0;
}

void ftpparser_module_destroy(void)
{
	textsearch_destroy(ts_config);
}

void parser_init(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset)
{
	parser->skb = skb;
	parser->line = NULL;
	parser->line_len = 0;
	parser->line_clean = 0;
	parser->line_next_offset = offset;
	INIT_LIST_HEAD(&parser->options);
}

void parser_init_continue(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset,
		char *unfinished_line,
		unsigned int unfinished_line_len,
		unsigned int unfinished_line_clean)
{
	parser_init(parser, skb, offset);
	parser->line = unfinished_line;
	parser->line_len = unfinished_line_len;
	parser->line_clean = unfinished_line_clean;
}

void parser_destroy(struct ftp_parser *parser)
{
	kfree(parser->line);
}

/*
 * Find the next line feed (LF) in the packet.
 * (We do not search for the full newline (CR LF) directly because there
 * can be Telnet noise between those two characters.)
 */
static unsigned int find_next_lf(struct ftp_parser *parser)
{
	struct ts_state state;
	memset(&state, 0, sizeof(state));
	/*
	 * We throw the state away because calls to textsearch_next() return the
	 * offset to the original parser->line_next_offset, not the new one.
	 * That just complicates things.
	 */
	return skb_find_text(parser->skb, parser->line_next_offset,
			parser->skb->len, ts_config, &state);
}

static int fetch_skb_bytes_until_lf(struct ftp_parser *parser)
{
	unsigned int skb_len;
	unsigned int total_len;
	bool truncated;
	int error;

	skb_len = find_next_lf(parser);
	if (skb_len == UINT_MAX) {
		truncated = true;
		skb_len = parser->skb->len - parser->line_next_offset;
	} else {
		truncated = false;
		skb_len++; /* Include the LF chara. */
	}

	total_len = skb_len + parser->line_len;
	/* "+ 1" = + null chara. */
	parser->line = krealloc(parser->line, total_len + 1, GFP_ATOMIC);
	if (!parser->line)
		return -ENOMEM;

	error = skb_copy_bits(parser->skb, parser->line_next_offset,
			parser->line + parser->line_len, skb_len);
	if (error) {
		log_debug("skb_copy_bits() threw errcode %d.", error);
		return error;
	}
	parser->line_len = total_len;
	parser->line_next_offset += skb_len;

	return truncated ? -ETRUNCATED : 0;
}

static int handle_option(struct ftp_parser *parser, unsigned int iac_offset)
{
	struct telnet_option *opt;

	opt = kmalloc(sizeof(*opt), GFP_ATOMIC);
	if (!opt)
		return -ENOMEM;

	/* LF != WILL/DO so there are at least two more charas. */
	opt->action = parser->line[iac_offset + 1];
	opt->code = parser->line[iac_offset + 2];
	list_add_tail(&opt->list_hook, &parser->options);

	return 0;
}

/*
 * This function can AND WILL assume @parser->line is LF-terminated.
 */
static int rm_telnet_noise(struct ftp_parser *parser)
{
	unsigned int from = parser->line_clean;
	unsigned int to = parser->line_clean;
	unsigned char chara;
	int error;

	while (from < parser->line_len) {
		while (IAC == (unsigned char)parser->line[from]) {
			/* LF != IAC so there IS at least one more chara. */
			chara = (unsigned char)parser->line[from + 1];
			if (chara == IAC) {
				/* Waste the escape character. */
				from++;
				break;
			} else if (chara == WILL || chara == DO) {
				error = handle_option(parser, from);
				if (error)
					return error;
				/* Waste the IAC, the WILL/DO and the option. */
				from += 3;
			} else {
				/* Waste the IAC and the command. */
				from += 2;
			}

			if (from >= parser->line_len)
				goto end;
		}

		parser->line[to++] = parser->line[from++];
	}
	/* Fall though. */

end:
	parser->line_len -= from - to;
	parser->line_clean = parser->line_len;
	return 0;
}

static bool is_newline_terminated(struct ftp_parser *parser)
{
	char char1 = parser->line[parser->line_len - 2];
	char char2 = parser->line[parser->line_len - 1];
	return char1 == '\r' && char2 == '\n';
}

/**
 * Copies the next line of text (until CR LF) from the stream to *@line,
 * ignoring (cleaning) any Telnet noise from the stream.
 *
 * If the packet does not fully contain the next line, it leaves the content
 * (Telnet dirty) in @parser->line and returns -ETRUNCATED.
 */
int parser_next_line(struct ftp_parser *parser, char **line)
{
	int error;

	if (parser->line_next_offset >= parser->skb->len)
		return EOP;

	do {
		error = fetch_skb_bytes_until_lf(parser);
		if (error)
			return error;
		/*
		 * Note: This isn't outside of the while because there can be
		 * Telnet noise between CR and LF. We need to clean before we
		 * query.
		 */
		error = rm_telnet_noise(parser);
		if (error)
			return error;
	} while (!is_newline_terminated(parser));

	parser->line[parser->line_len] = '\0';
	*line = parser->line;
	parser->line = NULL;
	parser->line_len = 0;
	parser->line_clean = 0;
	return 0;
}

/**
 * Assumes @line's length >= @expected's length.
 */
bool line_starts_with(char *line, char *expected)
{
	/* RFC 1123 section 5.3. */
	return strncasecmp(line, expected, strlen(expected)) == 0;
}
