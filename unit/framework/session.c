#include "nat64/unit/session.h"
#include "nat64/common/str_utils.h"

static int count_sessions(struct session_entry *session, void *arg)
{
	u16 *result = arg;
	(*result)++;
	return 0;
}

bool session_assert(l4_protocol l4_proto, struct session_entry **expected_sessions)
{
	int expected_count = 0;
	int actual_count = 0;
	int error;

	if (is_error(sessiondb_for_each(l4_proto, count_sessions, &actual_count))) {
		log_err("Could not count the session entries in the database for some reason.");
		return false;
	}

	while (expected_sessions && expected_sessions[expected_count]) {
		struct session_entry *expected = expected_sessions[expected_count];
		struct session_entry *actual;
		struct tuple tuple6;

		tuple6.dst.addr6 = expected->local6;
		tuple6.src.addr6 = expected->remote6;
		tuple6.l3_proto = L3PROTO_IPV6;
		tuple6.l4_proto = expected->l4_proto;

		error = sessiondb_get(&tuple6, &actual);
		if (error) {
			log_err("Error %d while trying to find session entry %d [%pI6c#%u, %pI6c#%u, "
					"%pI4#%u, %pI4#%u] in the DB.", error, expected_count,
					&expected->remote6.l3, expected->remote6.l4,
					&expected->local6.l3, expected->local6.l4,
					&expected->local4.l3, expected->local4.l4,
					&expected->remote4.l3, expected->remote4.l4);
			return false;
		}

		expected_count++;
	}

	if (expected_count != actual_count) {
		log_err("Expected %d session entries in the database. Found %d.", expected_count,
				actual_count);
		return false;
	}

	return true;
}

static int session_print_aux(struct session_entry *session, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI6c#%u, %pI4#%u, %pI4#%u]",
			session->bib->is_static ? "Static" : "Dynamic",
			&session->remote6.l3, session->remote6.l4,
			&session->local6.l3, session->local6.l4,
			&session->local4.l3, session->local4.l4,
			&session->remote4.l3, session->remote4.l4);
	return 0;
}

int session_print(l4_protocol l4_proto)
{
	log_debug("Sessions:");
	return sessiondb_for_each(l4_proto, session_print_aux, NULL);
}

struct session_entry *session_create_str(unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum l4_protocol l4_proto)
{
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;

	if (is_error(str_to_addr6(remote6_addr, &remote6.l3)))
		return NULL;
	remote6.l4 = remote6_id;
	if (is_error(str_to_addr6(local6_addr, &local6.l3)))
		return NULL;
	local6.l4 = local6_id;

	if (is_error(str_to_addr4(local4_addr, &local4.l3)))
		return NULL;
	local4.l4 = local4_id;
	if (is_error(str_to_addr4(remote4_addr, &remote4.l3)))
		return NULL;
	remote4.l4 = remote4_id;

	return session_create(&remote6, &local6, &local4, &remote4, l4_proto, NULL);
}

struct session_entry *session_create_str_tcp(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_state state)
{
	struct session_entry *session;

	session = session_create_str(remote6_addr, remote6_id, local6_addr, local6_id, local4_addr,
			local4_id, remote4_addr, remote4_id, L4PROTO_TCP);
	if (!session)
		return NULL;

	session->state = state;
	return session;
}

struct session_entry *session_inject_str(unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		l4_protocol l4_proto, enum session_timer_type timer_type)
{
	struct session_entry *session;
	session = session_create_str(remote6_addr, remote6_id, local6_addr, local6_id,
			local4_addr, local4_id, remote4_addr, remote4_id, l4_proto);
	return (sessiondb_add(session, timer_type) != 0) ? NULL : session;
}
