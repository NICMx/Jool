#include "instance.h"

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
	struct request_instance_add request;
	int error;

	error = validate_instance_name(name);
	if (error)
		return error;

	request.type = type;
	strcpy(request.name, name);
	return JNL_SIMPLE_REQUEST(NULL, MODE_INSTANCE, OP_ADD, request);
}

int instance_rm(char *name)
{
	struct request_instance_rm request;
	int error;

	error = validate_instance_name(name);
	if (error)
		return error;

	strcpy(request.name, name);
	return JNL_SIMPLE_REQUEST(NULL, MODE_INSTANCE, OP_REMOVE, request);
}
