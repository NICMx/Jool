#ifndef _JOOL_MOD_ALG_FTP_PARSER_H
#define _JOOL_MOD_ALG_FTP_PARSER_H

#include <linux/skbuff.h>


enum ftp_client_code {
	FTP_AUTH,
	FTP_EPSV,
	FTP_EPRT,
	FTP_ALGS,
};

/** See http://tools.ietf.org/html/rfc2428#section-3 */
enum epsv_type {
	/** The EPSV command contains no arguments. */
	EPSV_EMPTY,
	/** The EPSV command contains the "net-prt" field. */
	EPSV_CONTAINS_PROTO,
	/** Command is an "EPSV ALL". */
	EPSV_ALL,
};

enum alg_argument {
	ALGS_STATUS64,
	ALGS_ENABLE64,
	ALGS_DISABLE64,
	ALGS_BAD_SYNTAX,
};

struct ftp_client_msg {
	enum ftp_client_code code;

	union {
		struct {
			enum epsv_type type;
			/*
			 * RFC 2448  calls this "net-prt".
			 * This is only relevant if @type is
			 * EPSV_CONTAINS_PROTO.
			 */
			unsigned int proto;
		} epsv;
		struct {
			unsigned int proto;
			/* RFC 2448 calls this "net-addr" and "tcp-port". */
			union {
				struct ipv4_transport_addr addr4;
				struct ipv6_transport_addr addr6;
			};
		} eprt;
		struct {
			enum alg_argument arg;
		} algs;
	};
};

enum ftp_server_code {
	/* Entering passive mode. */
	FTP_227,
	/* 4xx or 5xx. */
	FTP_REJECT,
};

struct ftp_server_msg {
	enum ftp_server_code code;
	union {
		struct {
			struct ipv4_transport_addr addr;
		} epsv_227;
	};
};

struct ftp_token {
	char *name;
	unsigned int code;
};

struct ftp_ctrl_channel_parser {
	struct sk_buff *skb;
	struct list_head options;

	unsigned char buffer[128];
	unsigned int skb_offset;
	unsigned int buffer_offset;
};


struct ftp_ctrl_channel_parser *ftpparser_create(struct sk_buff *skb);
int ftpparser_server_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_server_msg *token);
int ftpparser_client_nextline(struct ftp_ctrl_channel_parser *parser,
		struct ftp_client_msg *token);
void ftpparser_destroy(struct ftp_ctrl_channel_parser *parser);


#endif /* _JOOL_MOD_ALG_FTP_PARSER_H */
