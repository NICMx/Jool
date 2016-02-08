#include "nat64/usr/instance.h"

#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)

int instance_add(void)
{
	struct request_hdr hdr;
	/*
	 * TODO this is redundant;
	 * it should receive payload length instead of total.
	 */
	init_request_hdr(&hdr, sizeof(hdr), MODE_INSTANCE, OP_ADD);
	/*
	 * TODO does this function really need to receive length?
	 * The request always starts with a struct request_hdr AFAIK.
	 */
	return netlink_request(&hdr, hdr.length, NULL, NULL);
}

int instance_rm(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, sizeof(hdr), MODE_INSTANCE, OP_REMOVE);
	return netlink_request(&hdr, hdr.length, NULL, NULL);
}
