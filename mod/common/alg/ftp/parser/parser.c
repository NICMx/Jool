#include "nat64/mod/common/alg/ftp/parser/parser.h"
/* TODO rm */
#include "nat64/mod/common/types.h"

#define WILL	251
#define DO	253
#define IAC	255
#define NEWLINE	-1
#define CRLF	"\r\n"

static struct ts_config *ts_config;

int ftpparser_module_init(void)
{
	ts_config = textsearch_prepare("kmp", CRLF, strlen(CRLF), GFP_KERNEL,
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
	memset(&parser->ts_state, 0, sizeof(parser->ts_state));
	parser->ts_state_initialized = false;
	parser->line = NULL;
	parser->line_len = 0;
	parser->line_next_offset = offset;
	/* parser->chara = ; */
	/* parser->chara_offset = ; */
	INIT_LIST_HEAD(&parser->options);
}

void parser_init_continue(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset,
		char *unfinished_line,
		size_t unfinished_line_len)
{
	parser_init(parser, skb, offset);
	parser->line = unfinished_line;
	parser->line_len = unfinished_line_len;
}

void parser_destroy(struct ftp_parser *parser)
{
	kfree(parser->line);
}

static int __fetch_next_chara(struct ftp_parser *parser, unsigned char *chara)
{
	if (parser->chara_offset >= parser->line_len)
		return -ENOENT; /* TODO this might mean something unintended. */
	*chara = parser->line[parser->chara_offset];
	parser->chara_offset++;
	return 0;
}

static int handle_option(struct ftp_parser *parser, unsigned char action)
{
	struct telnet_option *option;
	unsigned char code;
	int error;

	error = __fetch_next_chara(parser, &code);
	if (error)
		return error;
	option = kmalloc(sizeof(*option), GFP_ATOMIC);
	if (!option)
		return -ENOMEM;

	option->action = action;
	option->code = code;
	option->offset = parser->line_next_offset + parser->chara_offset;
	list_add_tail(&option->list_hook, &parser->options);
	return 0;
}

static bool is_printable(int chara)
{
	return 31 < chara && chara < 127;
}

static void report_fetched_chara(int chara)
{
	if (is_printable(chara)) {
		log_debug("Fetched chara: '%c'", chara);
	} else {
		log_debug("Fetched chara: %d", chara);
	}
}

/**
 * Copy the next "relevant" character from parser->buffer to parser->chara.
 *
 * "Irrelevant" characters are Telnet noise. Callers can assume this function
 * will clean the stream for them.
 */
static int fetch_next_chara(struct ftp_parser *parser)
{
	unsigned char chara;
	int error;

	error = __fetch_next_chara(parser, &chara);
	if (error)
		return error;

	while (chara == IAC) {
		error = __fetch_next_chara(parser, &chara);
		if (error)
			return error;

		if (chara == IAC)
			break; /* Character is an escaped 255. */
		if (chara == WILL || chara == DO) {
			error = handle_option(parser, chara);
			if (error)
				return error;
		}

		/* Leave the cursor at the next thing after the command. */
		error = __fetch_next_chara(parser, &chara);
		if (error)
			return error;
	};

	parser->chara = (parser->chara == '\r' && chara == '\n')
			? NEWLINE
			: chara;
	report_fetched_chara(parser->chara);
	return 0;
}

/**
 * Copies the next line of text from the stream to @parser->line.
 *
 * If the packet does not fully contain the next line, it fetches the content
 * anyway and returns -ETRUNCATED.
 *
 * TODO this will fail to find the newline if there's telnet bullshit between CR and LF.
 */
static int fetch_next_line(struct ftp_parser *parser)
{
	unsigned int skb_len;
	unsigned int total_len;
	bool newline_found = true;
	int error;

	if (parser->line_next_offset >= parser->skb->len) {
		log_debug("Ok, no more lines.");
		return EOP;
	}

	/* Find the next newline (CR LF). */
	if (!parser->ts_state_initialized) {
		skb_len = skb_find_text(parser->skb, parser->line_next_offset,
				parser->skb->len, ts_config, &parser->ts_state);
		parser->ts_state_initialized = true;
	} else {
		skb_len = textsearch_next(ts_config, &parser->ts_state);
	}

	if (skb_len == UINT_MAX) {
		newline_found = false;
		skb_len = parser->skb->len - parser->line_next_offset;
	}

	total_len = skb_len + parser->line_len;
	parser->line = krealloc(parser->line, total_len, GFP_ATOMIC);
	if (!parser->line)
		return -ENOMEM;

//	log_debug("skb->len: %u", parser->skb->len);
//	log_debug("parser->line_next_offset: %u", parser->line_next_offset);
//	log_debug("skb_len: %u", skb_len);
//	log_debug("total_len: %u", total_len);
//	log_debug("newline found: %d", newline_found);

	error = skb_copy_bits(parser->skb, parser->line_next_offset,
			parser->line + parser->line_len, skb_len);
	if (error) {
		log_debug("skb_copy_bits() threw errcode %d.", error);
		return error;
	}
	parser->line_len = total_len;
	parser->line_next_offset += skb_len + strlen(CRLF);
	parser->chara_offset = 0;

	return newline_found ? 0 : -ETRUNCATED;
}

/**
 * Consumes what's left of the current line from @parser's stream, copying it to
 * @line.
 *
 * If the line is longer than line_len, returns -EINVAL.
 */
int next_line(struct ftp_parser *parser, char **line)
{
	char *result;
	unsigned int pos = 0;
	int error;

	/* TODO multiline commands yield lines that don't start with the token. */

	error = fetch_next_line(parser);
	if (error)
		return error;

	/* Original string + null chara. */
	result = kmalloc(parser->line_len + 1, GFP_ATOMIC);
	if (!result) {
		error = -ENOMEM;
		goto end;
	}

	while (parser->chara_offset < parser->line_len) {
		error = fetch_next_chara(parser);
		if (error) {
			kfree(result);
			goto end;
		}

		/*
		 * This validation is mostly to prevent CR from leaking into the
		 * line, though it IS nice that it helps line be char instead of
		 * unsigned char.
		 */
		if (is_printable(parser->chara))
			result[pos++] = parser->chara;
	};

	result[pos] = '\0';
	*line = result;
	/* Fall through. */

end:
	kfree(parser->line);
	parser->line = NULL;
	parser->line_len = 0;
	return error;
}

/**
 * Assumes @line's length >= @expected's length.
 */
bool line_starts_with(char *line, char *expected)
{
	/* RFC 1123 section 5.3. */
	return strncasecmp(line, expected, strlen(expected)) == 0;
}
