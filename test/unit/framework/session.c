#include "nat64/unit/session.h"

#include "nat64/common/str_utils.h"

static int session_print_aux(struct session_entry *session, void *arg)
{
	log_debug("  [%s][%pI6c#%u, %pI6c#%u, %pI4#%u, %pI4#%u]",
			session->bib->is_static ? "Static" : "Dynamic",
			&session->src6.l3, session->src6.l4,
			&session->dst6.l3, session->dst6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);
	return 0;
}

int session_print(struct sessiondb *db, l4_protocol l4_proto)
{
	log_debug("Sessions:");
	return sessiondb_foreach(db, l4_proto, session_print_aux, NULL, NULL,
			NULL);
}

struct session_entry *session_inject(struct sessiondb *db,
		char *remote6_addr, u16 remote6_id,
		char *local6_addr, u16 local6_id,
		char *local4_addr, u16 local4_id,
		char *remote4_addr, u16 remote4_id,
		l4_protocol proto, bool is_est)
{
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	struct session_entry *session;

	if (str_to_addr6(remote6_addr, &remote6.l3))
		return NULL;
	remote6.l4 = remote6_id;
	if (str_to_addr6(local6_addr, &local6.l3))
		return NULL;
	local6.l4 = local6_id;

	if (str_to_addr4(local4_addr, &local4.l3))
		return NULL;
	local4.l4 = local4_id;
	if (str_to_addr4(remote4_addr, &remote4.l3))
		return NULL;
	remote4.l4 = remote4_id;

	session = session_create(&remote6, &local6, &local4, &remote4, proto,
			NULL);
	if (!session)
		return NULL;

	return sessiondb_add(db, session, NULL, NULL) ? NULL : session;
}
