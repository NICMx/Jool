#ifndef _JOOL_MOD_ALG_FTP_STATE_ENTRY_H
#define _JOOL_MOD_ALG_FTP_STATE_ENTRY_H

struct ftp_state {
	bool	algs_requested : 1,

		client_sent_auth : 1,
		client_sent_epsv : 1,

		transparent_mode : 1;
};

#endif /* _JOOL_MOD_ALG_FTP_STATE_ENTRY_H */
