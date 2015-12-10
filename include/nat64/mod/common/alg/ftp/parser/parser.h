#ifndef _JOOL_MOD_ALG_FTP_PARSER_H
#define _JOOL_MOD_ALG_FTP_PARSER_H

#include <linux/types.h>
#include <linux/skbuff.h>

/* TODO Align to page size so we can harness the whole allocated chunk? */
#define BUFFER_LEN 1024

struct ftp_parser {
	struct sk_buff *skb;
	unsigned int skb_offset;

	/* It's unsigned because endpoints can negotiate encoding. */
	unsigned char buffer[BUFFER_LEN];
	unsigned int buffer_len;
	unsigned int buffer_offset;

	/**
	 * Last character read from the packet.
	 * Can be any unsigned char character, but (unlike @buffer's characters)
	 * can also be -1, which is @NEWLINE.
	 */
	int chara;

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

struct ftp_parser *parser_create(struct sk_buff *skb, unsigned int skb_offset);
void parser_destroy(struct ftp_parser *parser);

int next_word(struct ftp_parser *parser, struct ftp_word *word);
int next_line(struct ftp_parser *parser, char *line, size_t line_len);
int next_u8(struct ftp_parser *parser, u8 *result);

int waste_line(struct ftp_parser *parser);
int waste_until(struct ftp_parser *parser, char delimiter);

bool word_equals(struct ftp_word *word, char *expected);
bool line_starts_with(char *line, char *expected);

#endif /* _JOOL_MOD_ALG_FTP_PARSER_H */
