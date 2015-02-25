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

#define PKT_PAYLOAD_LEN sizeof(struct usr_skb_pkt)
int send_packet(void *pkt, __u32 pkt_len, char *filename, __u32 str_len, enum config_mode mode,
		enum config_operation op)
{
	unsigned char request[HDR_LEN + PKT_PAYLOAD_LEN + pkt_len + str_len];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct usr_skb_pkt *payload = (struct usr_skb_pkt *) (hdr + 1);

	log_debug("Sending packet to the kernel module.");

	hdr->len = PKT_PAYLOAD_LEN + pkt_len + str_len;
	hdr->mode = mode;
	hdr->operation = op;

	payload->pkt = (void *) (payload + 1);
	payload->pkt_len = pkt_len;
	payload->filename = (char *) (payload->pkt + pkt_len);
	payload->filename_len = str_len;

	memcpy(payload->pkt, pkt, pkt_len);
	memcpy(payload->filename, filename, str_len);

	return netlink_request(request, HDR_LEN + PKT_PAYLOAD_LEN + pkt_len + str_len,
			handle_send_pkt_response, NULL);
}


static int handle_flush_op_response(struct nl_msg *msg, void *arg)
{
	log_debug("Database flushed.");
	return 0;
}

int send_flush_op(enum config_mode mode, enum config_operation op)
{
	unsigned char request[HDR_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;

	log_debug("Sending op to the kernel module.");
	hdr->len = HDR_LEN;
	hdr->mode = mode;
	hdr->operation = op;

	return netlink_request(request, HDR_LEN, handle_flush_op_response, NULL);
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	log_info("Value changed successfully.");
	return 0;
}

int global_update(__u8 type, size_t size, void *data)
{
	unsigned char request[HDR_LEN + size];
	struct request_hdr *hdr = (struct request_hdr *) request;
	/*union request_global *global_hdr;*/
	void *payload;

	payload = hdr + 1;

	hdr->len = size;
	hdr->mode = MODE_BYTE;
	hdr->operation = OP_ADD;
	/*global_hdr->update.type = type;*/
	memcpy(payload, data, size);

	return netlink_request(hdr, HDR_LEN + size, handle_update_response, NULL);
}

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	log_info("Printed in the kernel log, use dmesg to see it.");
	return 0;
}

int general_display_array(void)
{
	log_info("Requesting the byte array list.");
	struct request_hdr request = {
		.len = sizeof(request),
		.mode = MODE_BYTE,
		.operation = OP_DISPLAY,
	};
	return netlink_request(&request, request.len, handle_display_response, NULL);
}

int receiver_display(void)
{
	log_info("Requesting the Receiver stats.");
	struct request_hdr request = {
		.len = sizeof(request),
		.mode = MODE_RECEIVER,
		.operation = OP_DISPLAY,
	};
	return netlink_request(&request, request.len, handle_display_response, NULL);
}
