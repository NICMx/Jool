#ifndef _JOOL_MOD_ALG_FTP_PARSER_TELNET_H
#define _JOOL_MOD_ALG_FTP_PARSER_TELNET_H

#include <linux/list.h>
#include <linux/skbuff.h>

enum telnet_type {
	TELNET_COMMAND,
	TELNET_OPT,
	TELNET_TEXT,
};

struct telnet_chunk {
	enum telnet_type type;
	unsigned int offset;
	char prefix[4];
	struct list_head list_hook;
};

int telnet_parse(struct sk_buff *skb, unsigned int offset,
		struct list_head *chunks);

struct telnet_chunk *telnet_chunk_entry(struct list_head *node);

#endif /* _JOOL_MOD_ALG_FTP_PARSER_TELNET_H */
