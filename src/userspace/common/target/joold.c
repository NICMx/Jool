#include "nat64/usr/joold.h"

#include <stddef.h>
#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

int joold_advertise(void)
{
	int error = 0;
	struct request_hdr request;

	init_request_hdr(&request, MODE_JOOLD, OP_ADVERTISE);
	error = netlink_request(&request, sizeof(request), NULL, NULL);

	return error;
}

int joold_test(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_TEST);
	return netlink_request(&hdr, sizeof(hdr), NULL, NULL);
}
