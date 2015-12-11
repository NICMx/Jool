#include "nat64/mod/common/alg/ftp/parser/parser.h"
/* TODO rm */
#include "nat64/mod/common/types.h"

#define WILL	251
#define DO	253
#define IAC	255
#define NEWLINE	-1

struct ftp_parser *parser_create(struct sk_buff *skb, unsigned int skb_offset)
{
	struct ftp_parser *parser;

	parser = kmalloc(sizeof(*parser), GFP_ATOMIC);
	if (!parser)
		return NULL;

	parser->skb = skb;
	parser->skb_offset = skb_offset;

	/* unsigned char buffer[BUFFER_LEN]; */
	parser->buffer_len = 0;
	parser->buffer_offset = 1;

	/* int chara; */

	INIT_LIST_HEAD(&parser->options);
	return parser;
}

void parser_destroy(struct ftp_parser *parser)
{
	kfree(parser);
}

/**
 * Copies the next bunch of bytes from parser->skb to parser's buffer.
 *
 * We don't access skb bytes directly because paging and fragmentation can make
 * it complicated.
 */
int fetch_next_block(struct ftp_parser *parser)
{
	struct sk_buff *skb = parser->skb;
	unsigned int read_len;
	int error;

	read_len = (parser->skb_offset + BUFFER_LEN > skb->len)
			? (skb->len - parser->skb_offset)
			: BUFFER_LEN;
	if (read_len == 0)
		return -ENOENT;
	error = skb_copy_bits(skb, parser->skb_offset, parser->buffer, read_len);
	if (error)
		return error;

	parser->skb_offset += read_len;
	parser->buffer_len = read_len;
	parser->buffer_offset = 0;
	return 0;
}

/**
 * Simple-minded copy the next character from parser->buffer to parser->chara.
 */
int __fetch_next_chara(struct ftp_parser *parser, unsigned char *chara)
{
	int error;

	if (parser->buffer_offset >= parser->buffer_len) {
		error = fetch_next_block(parser);
		if (error)
			return error;
	}

	*chara = parser->buffer[parser->buffer_offset];
	parser->buffer_offset++;
	return 0;
}

int handle_option(struct ftp_parser *parser, unsigned char action)
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
	option->offset = parser->skb_offset + parser->buffer_offset;
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
int fetch_next_chara(struct ftp_parser *parser)
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

static bool is_alphanumeric(unsigned char chara)
{
	return ('0' <= chara && chara <= '9')
			|| ('A' <= chara && chara <= 'Z')
			|| ('a' <= chara && chara <= 'z');
}

static void word_add_chara(struct ftp_word *word, unsigned char chara)
{
	if (word->len >= ARRAY_SIZE(word->charas))
		return;

	word->charas[word->len] = chara;
	word->len++;
}

static void report_word(struct ftp_word *word)
{
	log_debug("Fetched word: [%.9s] (length %u)", word->charas, word->len);
}

/**
 * Consumes only the next word (alphanumeric token) from @parser's stream,
 * and copies its prefix (up to ARRAY_SIZE(word->charas) bytes) to @word.
 *
 * (It is assumed further characters are irrelevant.)
 */
int next_word(struct ftp_parser *parser, struct ftp_word *word)
{
	int error;

	memset(word->charas, 0, sizeof(word->charas)); /* TODO rm? */
	word->len = 0;
	do {
		error = fetch_next_chara(parser);
		if (error)
			return error;

		if (!is_alphanumeric(parser->chara))
			break;

		word_add_chara(word, parser->chara);
	} while (true);

	report_word(word);
	return 0;
}

static int line_add_chara(char *line, size_t line_len, unsigned int *pos,
		char chara)
{
	if (!line)
		return 0;
	if ((*pos) >= line_len)
		return -EINVAL;

	line[*pos] = chara;
	(*pos)++;
	return 0;
}

/**
 * Consumes what's left of the current line from @parser's stream, copying it to
 * @line.
 *
 * If the line is longer than line_len, returns -EINVAL.
 */
int next_line(struct ftp_parser *parser, char *line, size_t line_len)
{
	unsigned int pos = 0;
	int error;

	/*
	 * Only read if we're not at the end of a line.
	 * This prevents consecutive waste_line() calls from accidentally
	 * skipping lines.
	 * All FTP lines start with a token that MUST be parsed using
	 * read_word() anyway.
	 *
	 * TODO multiline commands yield lines that don't start with the token.
	 */
	if (parser->chara == NEWLINE)
		return line_add_chara(line, line_len, &pos, '\0');

	do {
		error = fetch_next_chara(parser);
		if (error)
			return error;

		if (parser->chara == NEWLINE)
			break;

		/**
		 * This validation is mostly to prevent CR from leaking into the
		 * line, though it IS nice that it helps line be char instead of
		 * unsigned char.
		 */
		if (!is_printable(parser->chara))
			continue;
		error = line_add_chara(line, line_len, &pos, parser->chara);
		if (error)
			return error;
	} while (true);

	return line_add_chara(line, line_len, &pos, '\0');
}

/**
 * Consumes and discards what's left of the current line from @parser's stream.
 */
int waste_line(struct ftp_parser *parser)
{
	int error;
	log_debug("-> Dropping the rest of the line...");
	error = next_line(parser, NULL, 0);
	log_debug("-> Done.");
	return error;
}

/**
 * Consumes only the next word (alphanumeric token) from @parser's stream, and
 * converts it to an 8-bit unsigned integer.
 */
int next_u8(struct ftp_parser *parser, u8 *result)
{
	struct ftp_word word;
	int error;

	error = next_word(parser, &word);
	if (error)
		return error;

	return kstrtou8(word.charas, 10, result);
}

/**
 * Consumes and discards all characters until @delimiter or newline.
 */
int waste_until(struct ftp_parser *parser, char delimiter)
{
	int error;

	do {
		error = fetch_next_chara(parser);
		if (error)
			return error;
	} while (parser->chara != delimiter && parser->chara != NEWLINE);

	return 0;
}

bool word_equals(struct ftp_word *word, char *expected)
{
	/* I need this because word->charas is not null-terminated. */
	if (word->len != strlen(expected))
		return false;

	/* RFC 1123 section 5.3. */
	return strncasecmp(word->charas, expected, word->len) == 0;
}

/**
 * Assumes @line's length >= @expected's length.
 */
bool line_starts_with(char *line, char *expected)
{
	return strncasecmp(line, expected, strlen(expected)) == 0;
}
