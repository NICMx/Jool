#include "instance.h"

#include "netlink.h"

/* TODO should be some other number. */
static const unsigned int MAX_NAME_LEN = 10;

static int validate_instance_name(char *name)
{
	if (strlen(name) > MAX_NAME_LEN) {
		log_err("Instance name is too long. (Max:%u)", MAX_NAME_LEN);
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
	return JNL_SIMPLE_REQUEST(MODE_INSTANCE, OP_ADD, request);
}

int instance_rm(char *name)
{
	struct request_instance_rm request;
	int error;

	error = validate_instance_name(name);
	if (error)
		return error;

	return JNL_SIMPLE_REQUEST(MODE_INSTANCE, OP_ADD, request);
}
