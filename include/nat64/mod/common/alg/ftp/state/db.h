#ifndef _JOOL_MOD_ALG_FTP_STATE_DB_H
#define _JOOL_MOD_ALG_FTP_STATE_DB_H

#include "nat64/mod/common/alg/ftp/state/entry.h"
#include "nat64/mod/common/packet.h"

struct ftp_state *ftpdb_get(struct packet *in);
struct ftp_state *ftpdb_get_or_create(struct packet *in);

#endif /* _JOOL_MOD_ALG_FTP_STATE_DB_H */
