#include "nat64/usr/filtering.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct filtering_config)

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	struct filtering_config *payload = (struct filtering_config *) (hdr + 1);

	if (hdr->result_code != ERR_SUCCESS) {
		print_code_msg(hdr->result_code, NULL);
		return EINVAL;
	}

	printf("Address dependent filtering (%s): %s\n", DROP_BY_ADDR_OPT,
			payload->drop_by_addr ? "ON" : "OFF");
	printf("Filtering of ICMPv6 info messages (%s): %s\n", DROP_ICMP6_INFO_OPT,
			payload->drop_icmp6_info ? "ON" : "OFF");
	printf("Dropping externally initiated TCP connections (%s): %s\n", DROP_EXTERNAL_TCP_OPT,
			payload->drop_external_tcp ? "ON" : "OFF");
	printf("UDP session lifetime (%s): %u seconds\n", UDP_TIMEOUT_OPT, payload->to.udp);
	printf("TCP established session lifetime (%s): %u seconds\n", TCP_EST_TIMEOUT_OPT,
			payload->to.tcp_est);
	printf("TCP transitory session lifetime (%s): %u seconds\n", TCP_TRANS_TIMEOUT_OPT,
			payload->to.tcp_trans);
	printf("ICMP session lifetime (%s): %u seconds\n", ICMP_TIMEOUT_OPT, payload->to.icmp);

	return 0;
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr->result_code, "Value changed successfully.");
	return 0;
}

int filtering_request(__u32 operation, struct filtering_config *config)
{
	if (operation == 0) {
		struct request_hdr request;

		request.length = sizeof(request);
		request.mode = MODE_FILTERING;
		request.operation = 0;

		return netlink_request(&request, request.length, handle_display_response);
	} else {
		unsigned char request[HDR_LEN + PAYLOAD_LEN];
		struct request_hdr *hdr = (struct request_hdr *) request;
		struct filtering_config *payload = (struct filtering_config *) (request + HDR_LEN);

		hdr->length = sizeof(request);
		hdr->mode = MODE_FILTERING;
		hdr->operation = operation;
		*payload = *config;

		return netlink_request(request, hdr->length, handle_update_response);
	}
}
