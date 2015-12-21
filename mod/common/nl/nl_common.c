#include <linux/netlink.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/version.h>

#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/nl/nl_core2.h"

int verify_superpriv(void) {
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required.");
		return -EPERM;
	}

	return 0;
}


