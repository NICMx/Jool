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

int send_packet(void *pkt, __u32 pkt_len, __u8 operation)
{
	unsigned char request[HDR_LEN + pkt_len];
	struct request_hdr *hdr = (struct request_hdr *) request;

	log_debug("Sending packet to the kernel module.");
	hdr->len = pkt_len;
	hdr->operation = operation;
	memcpy(request + HDR_LEN, pkt, pkt_len);

	return netlink_request(request, HDR_LEN + pkt_len,
			handle_send_pkt_response, NULL);
}

