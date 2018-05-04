#include "send.h"

#include <errno.h>
#include "common.h"
#include "nat64/common/types.h"
#include "nat64/usr/str_utils.h"

int send_init_request(int argc, char **argv, enum graybox_command *cmd,
		struct send_request *req)
{
	if (argc < 1) {
		log_err("Send requires a packet file as argument.");
		return -EINVAL;
	}

	*cmd = COMMAND_SEND;
	req->file_name = argv[0];
	return load_pkt(argv[0], &req->pkt, &req->pkt_len);
}

int send_build_pkt(struct send_request *req, struct nl_msg *pkt)
{
	int error;

	error = nla_put_string(pkt, ATTR_FILENAME, req->file_name);
	if (error)
		return error;

	return nla_put(pkt, ATTR_PKT, req->pkt_len, req->pkt);
}

void send_clean(struct send_request *req)
{
	if (req->pkt)
		free(req->pkt);
}
