#include "nat64/unit/session.h"
#include "nat64/comm/str_utils.h"

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

	while (expected_sessions[expected_count] != NULL) {
		struct session_entry *expected = expected_sessions[expected_count];
		struct session_entry *actual;
		struct tuple tuple6;

		tuple6.dst.addr.ipv6 = expected->ipv6.local.address;
		tuple6.dst.l4_id = expected->ipv6.local.l4_id;
		tuple6.src.addr.ipv6 = expected->ipv6.remote.address;
		tuple6.src.l4_id = expected->ipv6.remote.l4_id;
		tuple6.l3_proto = L3PROTO_IPV6;
		tuple6.l4_proto = expected->l4_proto;

		error = sessiondb_get(&tuple6, &actual);
		if (error) {
			log_err("Error %d while trying to find session entry %d [%pI6c#%u, %pI6c#%u, "
					"%pI4#%u, %pI4#%u] in the DB.", error, expected_count,
					&expected->ipv6.remote.address, expected->ipv6.remote.l4_id,
					&expected->ipv6.local.address, expected->ipv6.local.l4_id,
					&expected->ipv4.local.address, expected->ipv4.local.l4_id,
					&expected->ipv4.remote.address, expected->ipv4.remote.l4_id);
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
			&session->ipv6.remote.address, session->ipv6.remote.l4_id,
			&session->ipv6.local.address, session->ipv6.local.l4_id,
			&session->ipv4.local.address, session->ipv4.local.l4_id,
			&session->ipv4.remote.address, session->ipv4.remote.l4_id);
	return 0;
}

int session_print(l4_protocol l4_proto)
{
	log_debug("Sessions:");
	return sessiondb_for_each(l4_proto, session_print_aux, NULL);
}

struct session_entry *create_tcp_session(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_state state)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct session_entry *session;

	if (is_error(str_to_addr6(remote6_addr, &pair6.remote.address)))
		return NULL;
	pair6.remote.l4_id = remote6_id;
	if (is_error(str_to_addr6(local6_addr, &pair6.local.address)))
		return NULL;
	pair6.local.l4_id = local6_id;

	if (is_error(str_to_addr4(local4_addr, &pair4.local.address)))
		return NULL;
	pair4.local.l4_id = local4_id;
	if (is_error(str_to_addr4(remote4_addr, &pair4.remote.address)))
		return NULL;
	pair4.remote.l4_id = remote4_id;

	session = session_create(&pair4, &pair6, L4PROTO_TCP, NULL);
	session->state = state;
	return session;
}

