#include "nl/nl-common.h"

#include <linux/capability.h>
#include <linux/module.h>
#include "log.h"

int verify_privileges(void)
{
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required.");
		return -EPERM;
	}

	return 0;
}
