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

	/** Last chunk of data read from the packet. */
	char *line;
	/** Length of @line (it's not always null-terminated). */
	unsigned int line_len;
	/** Bytes from @line which have already been freed of Telnet noise. */
	unsigned int line_clean;
	/** Offset of the bytes that will be copied from @skb to @line next. */
	unsigned int line_next_offset;

	/**
	 * Telnet options the parser has found in the stream.
	 * We need to store these because we have to reject them.
	 */
	struct list_head options;
};

struct telnet_option {
	unsigned char action;
	unsigned char code;
	struct list_head list_hook;
};

int ftpparser_module_init(void);
void ftpparser_module_destroy(void);

void parser_init(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset);
/* TODO separate the unfinished fields for comfort? */
void parser_init_continue(struct ftp_parser *parser,
		struct sk_buff *skb,
		unsigned int offset,
		char *unfinished_line,
		unsigned int unfinished_line_len,
		unsigned int unfinished_line_clean);
void parser_destroy(struct ftp_parser *parser);

int parser_next_line(struct ftp_parser *parser, char **line);
bool line_starts_with(char *line, char *expected);

#endif /* _JOOL_MOD_ALG_FTP_PARSER_H */
