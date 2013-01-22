#include "mode.h"
#include "netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_translate)

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	union response_translate *payload = (union response_translate *) (hdr + 1);

	__u16 *plateaus;
	int i;

	if (hdr->result_code != RESPONSE_SUCCESS) {
		print_code_msg(hdr, "Translate", NULL);
		return hdr->result_code;
	}

	printf("packet_head_room: %u\n", payload->display.config.packet_head_room);
	printf("packet_tail_room: %u\n", payload->display.config.packet_tail_room);
	printf("Override IPv6 traffic class: %s\n",
			payload->display.config.override_ipv6_traffic_class ? "ON" : "OFF");
	printf("Override IPv4 traffic class: %s\n",
			payload->display.config.override_ipv4_traffic_class ? "ON" : "OFF");
	printf("IPv4 traffic class: %u\n", payload->display.config.ipv4_traffic_class);
	printf("DF flag always set: %s\n", payload->display.config.df_always_set ? "ON" : "OFF");
	printf("Generate IPv4 identification: %s\n",
			payload->display.config.generate_ipv4_id ? "ON" : "OFF");
	printf("Improve MTU failure rate: %s\n",
			payload->display.config.improve_mtu_failure_rate ? "ON" : "OFF");
	printf("IPv6 next hop MTU: %u\n", payload->display.config.ipv6_nexthop_mtu);
	printf("IPv4 next hop MTU: %u\n", payload->display.config.ipv4_nexthop_mtu);
	printf("MTU plateaus: ");

	plateaus = (__u16 *) (payload + 1);
	for (i = 0; i < payload->display.config.mtu_plateau_count; i++) {
		if (i + 1 != payload->display.config.mtu_plateau_count)
			printf("%u, ", plateaus[i]);
		else
			printf("%u\n", plateaus[i]);
	}

	return 0;
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "Translate", "Value changed successfully.");
	return 0;
}

error_t translate_request(__u32 operation, struct translate_config *config)
{
	if (operation == 0) {
		struct request_hdr request;

		request.length = sizeof(request);
		request.mode = MODE_TRANSLATE;
		request.operation = 0;

		return netlink_request(&request, request.length, handle_display_response);
	} else {
		struct request_hdr *hdr;
		union request_translate *payload_translate;
		__u16 *payload_mtus;
		__u16 request_len, mtus_len;
		error_t result;

		mtus_len = (operation & MTU_PLATEAUS_MASK)
				? (config->mtu_plateau_count * sizeof(*config->mtu_plateaus))
				: 0;
		request_len = sizeof(*hdr) + sizeof(*payload_translate) + mtus_len;
		hdr = malloc(request_len);
		if (!hdr)
			return RESPONSE_ALLOC_FAILED;
		payload_translate = (union request_translate *) (hdr + 1);
		payload_mtus = (__u16 *) (payload_translate + 1);

		hdr->length = request_len;
		hdr->mode = MODE_FILTERING;
		hdr->operation = operation;
		payload_translate->update.config = *config;
		memcpy(payload_mtus + 1, config->mtu_plateaus, mtus_len);

		result = netlink_request(hdr, request_len, handle_update_response);
		free(hdr);
		return result;
	}
}
