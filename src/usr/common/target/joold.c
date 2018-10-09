#include "usr/common/target/joold.h"

#include <stddef.h>
#include "common/config.h"
#include "usr/common/netlink.h"

int joold_advertise(char *iname)
{
	int error = 0;
	struct request_hdr request;

	init_request_hdr(&request, MODE_JOOLD, OP_ADVERTISE);
	error = netlink_request(iname, &request, sizeof(request), NULL, NULL);

	return error;
}

int joold_test(char *iname)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_TEST);
	return netlink_request(iname, &hdr, sizeof(hdr), NULL, NULL);
}
