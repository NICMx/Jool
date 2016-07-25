#include "nat64/unit/session.h"
#include "nat64/common/str_utils.h"

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
