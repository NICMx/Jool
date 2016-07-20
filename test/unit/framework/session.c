#include "nat64/unit/session.h"

#include "nat64/common/str_utils.h"

static int session_print_aux(struct session_entry *session, void *arg)
{
	log_debug("  [%pI6c#%u, %pI6c#%u, %pI4#%u, %pI4#%u]",
			&session->src6.l3, session->src6.l4,
			&session->dst6.l3, session->dst6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);
	return 0;
}

int session_print(struct bib *db, l4_protocol l4_proto)
{
	struct session_foreach_func func = {
			.cb = session_print_aux,
			.arg = NULL,
	};

	log_debug("Sessions:");
	return bib_foreach_session(db, l4_proto, &func, NULL);
}

int session_inject(struct bib *db,
		char *src6_addr, u16 src6_id,
		char *dst6_addr, u16 dst6_id,
		char *src4_addr, u16 src4_id,
		char *dst4_addr, u16 dst_id,
		l4_protocol proto, struct session_entry *session)
{
	int error;

	error = str_to_addr6(src6_addr, &session->src6.l3);
	if (error)
		return error;
	error = str_to_addr6(dst6_addr, &session->dst6.l3);
	if (error)
		return error;
	error = str_to_addr4(src4_addr, &session->src4.l3);
	if (error)
		return error;
	error = str_to_addr4(dst4_addr, &session->dst4.l3);
	if (error)
		return error;

	session->src6.l4 = src6_id;
	session->dst6.l4 = dst6_id;
	session->src4.l4 = src4_id;
	session->dst4.l4 = dst_id;

	return bib_add_session(db, session, NULL);
}
