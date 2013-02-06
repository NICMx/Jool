#include "mode.h"
#include "netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct filtering_config)

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	struct filtering_config *payload = (struct filtering_config *) (hdr + 1);

	if (hdr->result_code != RESPONSE_SUCCESS) {
		print_code_msg(hdr, "Filtering", NULL);
		return hdr->result_code;
	}

	printf("Address dependent filtering: %s\n",
			payload->address_dependent_filtering ? "ON" : "OFF");
	printf("Filtering of ICMPv6 info messages: %s\n",
			payload->filter_informational_icmpv6 ? "ON" : "OFF");
	printf("Dropping externally initiated TCP connections: %s\n",
			payload->drop_externally_initiated_tcp_connections ? "ON" : "OFF");

	return 0;
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "Filtering", "Value changed successfully.");
	return 0;
}

error_t filtering_request(__u32 operation, struct filtering_config *config)
{
	if (operation == 0) {
		struct request_hdr request;

		request.length = sizeof(request);
		request.mode = MODE_FILTERING;
		request.operation = 0;

		return netlink_single_request(&request, request.length, handle_display_response);
	} else {
		unsigned char request[HDR_LEN + PAYLOAD_LEN];
		struct request_hdr *hdr = (struct request_hdr *) request;
		struct filtering_config *payload = (struct filtering_config *) (request + HDR_LEN);

		hdr->length = sizeof(request);
		hdr->mode = MODE_FILTERING;
		hdr->operation = operation;
		*payload = *config;

		return netlink_single_request(request, hdr->length, handle_update_response);
	}
}
