#ifndef _JOOL_MOD_ALG_FTP_SM_H
#define _JOOL_MOD_ALG_FTP_SM_H

#include "nat64/mod/common/types.h"
#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"
#include "nat64/mod/common/alg/ftp/state/entry.h"


struct ftp_translated {
	bool payload_changed;
	size_t payload_len;
	struct list_head lines;

	/* TODO init? */
	struct sk_buff *skb;
};


/** Updates state. Should be called when the client sends an AUTH command. */
int ftpsm_client_sent_auth(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);
/** Updates state. Should be called when the client sends an EPSV command. */
int ftpsm_client_sent_epsv(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);
/** Updates state. Should be called when the client sends an EPRT command.*/
int ftpsm_client_sent_eprt(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);
/** Updates state. Should be called when the client sends an ALGS command.*/
int ftpsm_client_sent_algs(struct ftp_client_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);
int ftpsm_client_sent_whatever(struct ftp_client_msg *input,
		struct ftp_translated *output);

/** Updates state. Should be called when the server sends a 4xx or 5xx code. */
int ftpsm_server_denied(struct ftp_server_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);
/** Updates state. Should be called when the server sends a 227 code. */
int ftpsm_server_sent_227(struct ftp_server_msg *input,
		struct ftp_translated *output,
		struct ftp_state *state);

/** Updates state. Should be called last whenever a server packet is handled. */
void ftpsm_server_finished(struct ftp_state *state);

/** Have the endpoints successfully negotiated AUTH during state's session? */
bool ftpsm_is_transparent_mode(struct ftp_state *state);


#endif /* _JOOL_MOD_ALG_FTP_SM_H */
