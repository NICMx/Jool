#include "nat64/usr/fragmentation.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct fragmentation_config)

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct fragmentation_config *conf = nlmsg_data(nlmsg_hdr(msg));

	printf("Fragments arrival time slot (%s): ", FRAGMENTATION_TIMEOUT_OPT);
	print_time(conf->fragment_timeout);

	return 0;
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	log_info("Value changed successfully.");
	return 0;
}

int fragmentation_request(__u32 operation, struct fragmentation_config *config)
{
	if (operation == 0) {
		struct request_hdr request;

		request.length = sizeof(request);
		request.mode = MODE_FRAGMENTATION;
		request.operation = 0;

		return netlink_request(&request, request.length, handle_display_response, NULL);
	} else {
		unsigned char request[HDR_LEN + PAYLOAD_LEN];
		struct request_hdr *hdr = (struct request_hdr *) request;
		struct fragmentation_config *payload = (struct fragmentation_config *) (request + HDR_LEN);

		hdr->length = sizeof(request);
		hdr->mode = MODE_FRAGMENTATION;
		hdr->operation = operation;
		*payload = *config;

		return netlink_request(request, hdr->length, handle_update_response, NULL);
	}
}
