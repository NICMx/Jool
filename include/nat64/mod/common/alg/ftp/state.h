#ifndef _JOOL_MOD_ALG_FTP_STATE_H
#define _JOOL_MOD_ALG_FTP_STATE_H

#include "nat64/mod/common/packet.h"

int ftpstate_init(void);
void ftpstate_destroy(void);

/*
 * Store "client sent auth" as state for pkt's session.
 * This doesn't mean the communication is in transparent mode just yet.
 */
void ftpstate_client_sent_auth(struct packet *pkt);
/*
 * If the last client packet was an auth, purge state. Otherwise do nothing.
 */
void ftpstate_server_denied(struct packet *pkt);
/*
 * If the last client packet was an auth, and ftpstate_server_denied hasn't been
 * called, enter transparent mode.
 */
void ftpstate_server_finished(struct packet *pkt);

/* TODO Still need to handle session termination. */

bool ftpstate_is_transparent_mode(struct packet *pkt);

#endif /* _JOOL_MOD_ALG_FTP_STATE_H */
