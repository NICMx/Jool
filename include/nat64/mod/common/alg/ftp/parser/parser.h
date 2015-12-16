#ifndef _JOOL_MOD_ALG_FTP_PARSER_H
#define _JOOL_MOD_ALG_FTP_PARSER_H

#include <linux/types.h>
#include <linux/skbuff.h>

/**
 * "End of packet".
 * Is treated as an error code (for early termination purposes),
 * but the "E" doesn't stand for "error". Therefore, it should always be thrown
 * positive.
 * It means there were no more lines in the packet, so there is nothing left to
 * parse.
 */
#define EOP		59266
/**
 * Error version of "End of packet".
 * The packet ended but some FTP command was left hanging because there was no
 * newline.
 * Parsing of the command will have to wait until more data from the stream is
 * available.
 */
#define ETRUNCATED	59267

struct ftp_parser {
	struct sk_buff *skb;
	struct ts_state ts_state;
	bool ts_state_initialized;

	/*
	 * Last line of text (until the newline) read from the packet.
	 * It's unsigned because endpoints can negotiate encoding.
	 */
	unsigned char *line;
	unsigned int line_len;
	unsigned int line_next_offset;

	/**
	 * Last character read from @line.
	 * Can be any unsigned char character, but (unlike @buffer's characters)
	 * can also be -1, which is @NEWLINE.
	 */
	int chara;
	unsigned int chara_offset;

	struct list_head options;
};

struct telnet_option {
	unsigned char action;
	unsigned char code;
	unsigned int offset;
	struct list_head list_hook;
};

struct ftp_word {
	unsigned char charas[9];
	unsigned int len;
};

int ftpparser_module_init(void);
void ftpparser_module_destroy(void);

void parser_init(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset);
void parser_init_continue(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset,
		char *unfinished_line,
		size_t unfinished_line_len);
void parser_destroy(struct ftp_parser *parser);

int next_line(struct ftp_parser *parser, char **line);
bool line_starts_with(char *line, char *expected);

#endif /* _JOOL_MOD_ALG_FTP_PARSER_H */
