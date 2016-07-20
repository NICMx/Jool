#ifndef _JOOL_UNIT_SESSION_H
#define _JOOL_UNIT_SESSION_H

#include "nat64/mod/stateful/bib/db.h"

int session_print(struct bib *db, l4_protocol l4_proto);

int session_inject(struct bib *db,
		char *src6_addr, u16 src6_id,
		char *dst6_addr, u16 dst6_id,
		char *src4_addr, u16 src4_id,
		char *dst4_addr, u16 dst_id,
		l4_protocol proto, struct session_entry *session);

#endif /* _JOOL_UNIT_SESSION_H */
