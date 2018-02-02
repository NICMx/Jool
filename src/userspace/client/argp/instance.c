#include "instance.h"

#include <errno.h>
#include <string.h>

#include "types.h"
#include "netlink/instance.h"

int handle_instance_add(int argc, char **argv)
{
	xlator_type type;

	if (argc != 3) {
		log_err("Expected instance type and name as arguments.");
		return -EINVAL;
	}

	if (strcasecmp(argv[1], "SIIT") == 0)
		type = XLATOR_SIIT;
	else if (strcasecmp(argv[1], "NAT64") == 0)
		type = XLATOR_NAT64;
	else {
		log_err("Expected 'SIIT' or 'NAT64' as translator type.");
		return -EINVAL;
	}

	return instance_add(type, argv[1]);

}

int handle_instance_rm(int argc, char **argv)
{
	if (argc == 1) {
		log_err("Expected the instance's name as argument.");
		return -EINVAL;
	}
	if (argc > 2) {
		log_err("Expected only the instance's name as argument.");
		return -EINVAL;
	}

	return instance_rm(argv[0]);
}
