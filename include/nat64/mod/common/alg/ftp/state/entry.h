#ifndef _JOOL_MOD_ALG_FTP_STATE_ENTRY_H
#define _JOOL_MOD_ALG_FTP_STATE_ENTRY_H

#include "nat64/mod/common/types.h"


struct ftp_state {
	bool	algs_requested : 1,

		client_sent_auth : 1,
		client_sent_epsv : 1,

		transparent_mode : 1;
};


enum ftpxlat_action {
	FTPXLAT_DO_NOTHING,
	FTPXLAT_EPSV_TO_PASV,
	FTPXLAT_EPRT_TO_PORT,
	FTPXLAT_227_TO_229,
	FTPXLAT_RESPOND_STATUS,
	FTPXLAT_SYNTAX_ERROR,
};


/** Updates state. Should be called when the client sends an AUTH command. */
enum ftpxlat_action ftpsm_client_sent_auth(struct ftp_state *state);
/** Updates state. Should be called when the client sends an EPSV command. */
enum ftpxlat_action ftpsm_client_sent_epsv(struct ftp_state *state);
/** Updates state. Should be called when the client sends an EPRT command.*/
enum ftpxlat_action ftpsm_client_sent_eprt(struct ftp_state *state);
/** Updates state. Should be called when the client sends an ALGS command.*/
enum ftpxlat_action ftpsm_client_sent_algs(struct ftp_state *state,
		struct ftp_client_msg *token);

/** Updates state. Should be called when the server sends a 4xx or 5xx code. */
enum ftpxlat_action ftpsm_server_denied(struct ftp_state *state);
/** Updates state. Should be called when the server sends a 227 code. */
enum ftpxlat_action ftpsm_server_sent_227(struct ftp_state *state);

/** Updates state. Should be called last whenever a server packet is handled. */
enum ftpxlat_action ftpsm_server_finished(struct ftp_state *state);

/** Have the endpoints successfully negotiated AUTH during state's session? */
bool ftpsm_is_transparent_mode(struct ftp_state *state);


#endif /* _JOOL_MOD_ALG_FTP_STATE_ENTRY_H */
