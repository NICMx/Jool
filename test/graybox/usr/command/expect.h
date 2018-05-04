#ifndef _GRAYBOX_USR_CMD_EXPECT_H
#define _GRAYBOX_USR_CMD_EXPECT_H

#include <stddef.h>
#include <netlink/msg.h>
#include "types.h"

struct expect_add_request {
	char *file_name;
	unsigned char *pkt;
	size_t pkt_len;
	__u16 *exceptions;
	/* Number of exceptions; not number of bytes. */
	size_t exceptions_len;
};

int expect_init_request(int argc, char **argv, enum graybox_command *cmd,
		struct expect_add_request *req);
void expect_add_clean(struct expect_add_request *req);
int expect_add_build_pkt(struct expect_add_request *req, struct nl_msg *pkt);

#endif
