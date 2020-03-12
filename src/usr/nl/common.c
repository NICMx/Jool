#include "common.h"

#include <netlink/errno.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include "common/config.h"
#include "usr/nl/attribute.h"

struct jool_result joolnl_err_msgsize(void)
{
	return result_from_error(
		-NLE_NOMEM,
		"Cannot build Netlink request: Packet is too small."
	);
}

/* Boilerplate that needs to be done during every foreach response handler. */
struct jool_result joolnl_init_foreach(struct nl_msg *response,
		char const *what, bool *done)
{
	struct nlmsghdr *nhdr;
	struct genlmsghdr *ghdr;
	struct joolnlhdr *jhdr;

	nhdr = nlmsg_hdr(response);
	if (!genlmsg_valid_hdr(nhdr, sizeof(struct joolnlhdr))) {
		return result_from_error(
			-NLE_MSG_TOOSHORT,
			"The kernel module's response lacks headers."
		);
	}

	ghdr = genlmsg_hdr(nhdr);
	jhdr = genlmsg_user_hdr(ghdr);
	*done = !(jhdr->flags & HDRFLAGS_M);

	return jnla_validate_list(
		genlmsg_attrdata(ghdr, sizeof(struct joolnlhdr)),
		genlmsg_attrlen(ghdr, sizeof(struct joolnlhdr)),
		what,
		struct_list_policy
	);
}
