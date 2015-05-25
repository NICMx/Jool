#ifndef _JOOL_UNIT_SESSION_H
#define _JOOL_UNIT_SESSION_H

#include "nat64/mod/stateful/session/entry.h"
#include "nat64/common/session.h"


bool session_assert(l4_protocol l4_proto, struct session_entry **expected_sessions);
#define SESSION_ASSERT(l4_proto, ...) \
	session_assert(l4_proto, (struct session_entry*[]) { __VA_ARGS__ , NULL })
int session_print(l4_protocol l4_proto);

struct session_entry *session_create_str(unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum l4_protocol l4_proto);
struct session_entry *session_create_str_tcp(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_state state);

struct session_entry *session_inject(unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		l4_protocol l4_proto, bool is_est);


#endif /* _JOOL_UNIT_SESSION_H */
