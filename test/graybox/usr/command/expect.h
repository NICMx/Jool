#ifndef _GRAYBOX_USR_CMD_EXPECT_H
#define _GRAYBOX_USR_CMD_EXPECT_H

#include <stddef.h>
#include <netlink/msg.h>
#include "types.h"

#define PLATEAUS_MAX 64

struct expect_add_request {
	char *file_name;
	unsigned char *pkt;
	size_t pkt_len;
	/*
	 * This is not a plateaus array. PLATEAUS_MAX is a dumb hack, obviously.
	 * This is fine for now because no sane test would reach the
	 * PLATEAUS_MAX exceptions limit.
	 */
	__u16 exceptions[PLATEAUS_MAX];
	/* Number of exceptions; not number of bytes. */
	__u16 exceptions_len;
};

int expect_init_request(int argc, char **argv, enum graybox_command *cmd,
		struct expect_add_request *req);
void expect_add_clean(struct expect_add_request *req);
int expect_add_build_pkt(struct expect_add_request *req, struct nl_msg *pkt);

#endif
