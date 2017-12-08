#include "nat64/usr/instance.h"

#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)

int instance_add(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_INSTANCE, OP_ADD);
	return netlink_request(&hdr, sizeof(hdr), NULL, NULL);
}

int instance_rm(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_INSTANCE, OP_REMOVE);
	return netlink_request(&hdr, sizeof(hdr), NULL, NULL);
}
