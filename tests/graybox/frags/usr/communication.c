#include "communication.h"
#include "types.h"
#include "netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct configuration)


static int handle_send_pkt_response(struct nl_msg *msg, void *arg)
{
	log_debug("Packet sent successfully.");
	return 0;
}

int send_packet(void *pkt, __u32 pkt_len, enum operations op)
{
	unsigned char request[HDR_LEN + pkt_len];
	struct request_hdr *hdr = (struct request_hdr *) request;

	log_debug("Sending packet to the kernel module.");
	hdr->len = pkt_len;
	hdr->operation = op;
	memcpy(request + HDR_LEN, pkt, pkt_len);

	return netlink_request(request, HDR_LEN + pkt_len,
			handle_send_pkt_response, NULL);
}


static int handle_flush_op_response(struct nl_msg *msg, void *arg)
{
	log_debug("Database flushed.");
	return 0;
}
int send_flush_op(void)
{
	unsigned char request[HDR_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;

	log_debug("Sending op to the kernel module.");
	hdr->len = HDR_LEN;
	hdr->operation = OP_FLUSH_DB;

	return netlink_request(request, HDR_LEN, handle_flush_op_response, NULL);
}
