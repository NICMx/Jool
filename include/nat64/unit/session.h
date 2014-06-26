#ifndef _JOOL_UNIT_SESSION_H
#define _JOOL_UNIT_SESSION_H

#include "nat64/mod/session_db.h"


bool session_assert(l4_protocol l4_proto, struct session_entry **expected_sessions);
#define SESSION_ASSERT(l4_proto, ...) \
	session_assert(l4_proto, (struct session_entry*[]) { __VA_ARGS__ , NULL })
int session_print(l4_protocol l4_proto);


#endif /* _JOOL_UNIT_SESSION_H */
