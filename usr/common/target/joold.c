#include "nat64/usr/joold.h"

#include <stddef.h>
#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

int joold_advertise(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_ADVERTISE);
	return netlink_request(&hdr, sizeof(hdr), NULL, NULL);
}

int joold_test(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_TEST);
	return netlink_request(&hdr, sizeof(hdr), NULL, NULL);
}
