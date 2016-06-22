#ifndef _JOOL_UNIT_SESSION_H
#define _JOOL_UNIT_SESSION_H

#include "nat64/mod/stateful/session/db.h"

int session_print(struct sessiondb *db, l4_protocol l4_proto);

struct session_entry *session_inject(struct sessiondb *db,
		char *remote6_addr, u16 remote6_id,
		char *local6_addr, u16 local6_id,
		char *local4_addr, u16 local4_id,
		char *remote4_addr, u16 remote4_id,
		l4_protocol l4_proto);

#endif /* _JOOL_UNIT_SESSION_H */
