#include "device.h"
#include "types.h"
#include "netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_device)

static int handle_add_response(struct nl_msg *msg, void *arg)
{
	log_debug("Device name added successfully.");
	return 0;
}

int dev_add(char *device_name, __u32 name_len)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN + name_len];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_device *dev = (struct request_device *) (hdr + 1);

	dev->name = (char *) (dev + 1);
	dev->name_len = name_len;

	hdr->len = PAYLOAD_LEN + name_len;
	hdr->mode = MODE_DEVICE;
	hdr->operation = OP_ADD;

	memcpy(dev->name, device_name, name_len);

	return netlink_request(request, HDR_LEN + PAYLOAD_LEN + name_len,
			handle_add_response, NULL);
}

static int handle_remove_response(struct nl_msg *msg, void *arg)
{
	log_debug("Device name removed successfully.");
	return 0;
}

int dev_remove(char *device_name, __u32 name_len)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN + name_len];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_device *dev = (struct request_device *) (request + 1);

	dev->name = (char *) (dev + 1);
	dev->name_len = name_len;

	hdr->len = PAYLOAD_LEN + name_len;
	hdr->mode = MODE_DEVICE;
	hdr->operation = OP_REMOVE;

	memcpy(dev->name, device_name, name_len);

	return netlink_request(request, HDR_LEN + PAYLOAD_LEN + name_len,
			handle_remove_response, NULL);
}

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	log_info("Printed in the kernel log, use dmesg to see it.");
	return 0;
}

int dev_display(void) {
	log_info("Requesting the devices name list.");
	struct request_hdr request = {
		.len = HDR_LEN,
		.mode = MODE_DEVICE,
		.operation = OP_DISPLAY,
	};
	return netlink_request(&request, request.len, handle_display_response, NULL);
}

static int handle_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("Devices names flushed successfully.");
	return 0;
}

int dev_flush(void) {
	log_info("Flushing Device name DB.");
	struct request_hdr request = {
			.len = HDR_LEN,
			.mode = MODE_DEVICE,
			.operation = OP_FLUSH,
	};
	return netlink_request(&request, request.len, handle_flush_response, NULL);
}
