#include "joold.h"

#include <stddef.h>

#include "common/config.h"
#include "jool_socket.h"

struct jool_result joold_advertise(struct jool_socket *sk, char *iname)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_ADVERTISE, false);
	return netlink_request(sk, iname, &hdr, sizeof(hdr), NULL, NULL);
}

struct jool_result joold_test(struct jool_socket *sk, char *iname)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_JOOLD, OP_TEST, false);
	return netlink_request(sk, iname, &hdr, sizeof(hdr), NULL, NULL);
}
