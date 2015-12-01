#ifndef _JOOL_MOD_ALG_FTP_PARSER_H
#define _JOOL_MOD_ALG_FTP_PARSER_H

#include <linux/skbuff.h>

enum ftp_server_code {
	FTP_227,
	FTP_REJECT, /* 4xx, 5xx */
};

enum ftp_client_code {
	FTP_AUTH,
	FTP_EPSV,
	FTP_EPRT,
};

struct ftp_control_channel_parser {
	struct sk_buff *skb;
	struct list_head options;
};

int ftpparser_init(struct ftp_control_channel_parser *parser,
		struct sk_buff *skb);
int ftpparser_next(struct ftp_control_channel_parser *parser, char *line);
void ftpparser_destroy(struct ftp_control_channel_parser *parser);

enum ftp_server_code ftpparser_get_server_code(char *line);
enum ftp_client_code ftpparser_get_client_code(char *line);

#endif /* _JOOL_MOD_ALG_FTP_PARSER_H */
