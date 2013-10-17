#include "nat64/usr/filtering.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct filtering_config)

static void print_time(unsigned long millis)
{
	if (millis < 1000)
		printf("%lu milliseconds\n", millis);
	else if (millis < 1000 * 60)
		printf("%lu seconds\n", millis / 1000);
	else if (millis < 1000 * 60 * 60)
		printf("%lu minutes\n", millis / (1000 * 60));
	else
		printf("%lu hours\n", millis / (1000 * 60 * 60));
}

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct filtering_config *conf = nlmsg_data(nlmsg_hdr(msg));

	printf("Address dependent filtering (%s): %s\n", DROP_BY_ADDR_OPT,
			conf->drop_by_addr ? "ON" : "OFF");
	printf("Filtering of ICMPv6 info messages (%s): %s\n", DROP_ICMP6_INFO_OPT,
			conf->drop_icmp6_info ? "ON" : "OFF");
	printf("Dropping externally initiated TCP connections (%s): %s\n", DROP_EXTERNAL_TCP_OPT,
			conf->drop_external_tcp ? "ON" : "OFF");
	printf("UDP session lifetime (%s): ", UDP_TIMEOUT_OPT);
	print_time(conf->to.udp);
	printf("TCP established session lifetime (%s): ", TCP_EST_TIMEOUT_OPT);
	print_time(conf->to.tcp_est);
	printf("TCP transitory session lifetime (%s): ", TCP_TRANS_TIMEOUT_OPT);
	print_time(conf->to.tcp_trans);
	printf("ICMP session lifetime (%s): ", ICMP_TIMEOUT_OPT);
	print_time(conf->to.icmp);

	return 0;
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	log_info("Value changed successfully.");
	return 0;
}

int filtering_request(__u32 operation, struct filtering_config *config)
{
	if (operation == 0) {
		struct request_hdr request;

		request.length = sizeof(request);
		request.mode = MODE_FILTERING;
		request.operation = 0;

		return netlink_request(&request, request.length, handle_display_response, NULL);
	} else {
		unsigned char request[HDR_LEN + PAYLOAD_LEN];
		struct request_hdr *hdr = (struct request_hdr *) request;
		struct filtering_config *payload = (struct filtering_config *) (request + HDR_LEN);

		hdr->length = sizeof(request);
		hdr->mode = MODE_FILTERING;
		hdr->operation = operation;
		*payload = *config;

		return netlink_request(request, hdr->length, handle_update_response, NULL);
	}
}
