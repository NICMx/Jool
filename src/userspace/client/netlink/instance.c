#include "instance.h"

#include <netlink/attr.h>
#include <netlink/msg.h>
#include "netlink.h"

static int validate_instance_name(char *name)
{
	if (strlen(name) > IFNAMSIZ - 1) {
		log_err("Instance name is too long. (Max:%u)", IFNAMSIZ - 1);
		return -EINVAL;
	}

	return 0;
}

int instance_add(xlator_type type, char *name)
{
	struct nl_msg *request;
	int error;

	error = validate_instance_name(name);
	if (error)
		return error;

	error = jnl_create_request(name, JGNC_INSTANCE_ADD, &request);
	if (error)
		return error;

	error = nla_put_u8(request, JNLA_L4PROTO, type);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int instance_rm(char *name)
{
	struct nl_msg *request;
	int error;

	error = validate_instance_name(name);
	if (error)
		return error;

	error = jnl_create_request(name, JGNC_INSTANCE_RM, &request);
	if (error)
		return error;

	return jnl_single_request(request);
}
