#include "nat64/usr/eam.h"
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_eamt)

struct display_params {
	bool csv_format;
	unsigned int row_count;
	union request_eamt *req_payload;
};

static void print_eamt_entry(struct eamt_entry *entry, char *separator)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->prefix6.address, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->prefix4.address);
	printf("%s/%u", ipv6_str, entry->prefix6.len);
	printf("%s", separator);
	printf("%s/%u", ipv4_str, entry->prefix4.len);
	printf("\n");
}

static int eam_display_response(struct jool_response *response, void *arg)
{
	struct eamt_entry *entries = response->payload;
	struct display_params *params = arg;
	__u16 entry_count, i;

	entry_count = response->payload_len / sizeof(*entries);

	if (params->csv_format) {
		for (i = 0; i < entry_count; i++)
			print_eamt_entry(&entries[i], ",");
	} else {
		for (i = 0; i < entry_count; i++)
			print_eamt_entry(&entries[i], " - ");
	}

	params->row_count += entry_count;
	params->req_payload->display.prefix4_set = response->hdr->pending_data;
	if (entry_count > 0)
		params->req_payload->display.prefix4 = entries[entry_count - 1].prefix4;
	return 0;
}

int eam_display(bool csv)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);
	struct display_params params;
	int error;

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_DISPLAY);
	payload->display.prefix4_set = false;
	memset(&payload->display.prefix4, 0, sizeof(payload->display.prefix4));
	params.csv_format = csv;
	params.row_count = 0;
	params.req_payload = payload;

	if (csv)
		printf("IPv6 Prefix,IPv4 Prefix\n");

	do {
		error = netlink_request(request, hdr->length, eam_display_response, &params);
		if (error)
			return error;
	} while (payload->display.prefix4_set);

	if (!csv) {
		if (params.row_count > 0)
			log_info("  (Fetched %u entries.)", params.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static int eam_count_response(struct jool_response *response, void *arg)
{
	if (response->payload_len != sizeof(__u64)) {
		log_err("Jool's response is not the expected integer.");
		return -EINVAL;
	}

	printf("%llu\n", *((__u64 *)response->payload));
	return 0;
}

int eam_count(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_EAMT, OP_COUNT);
	return netlink_request(&request, request.length, eam_count_response, NULL);
}

int eam_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4, bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_ADD);
	payload->add.prefix4 = *prefix4;
	payload->add.prefix6 = *prefix6;
	payload->add.force = force;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int eam_remove(bool pref6_set, struct ipv6_prefix *prefix6, bool pref4_set,
		struct ipv4_prefix *prefix4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_REMOVE);
	payload->rm.prefix4_set = pref4_set;
	payload->rm.prefix4 = *prefix4;
	payload->rm.prefix6_set = pref6_set;
	payload->rm.prefix6 = *prefix6;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int eam_flush(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_EAMT, OP_FLUSH);
	return netlink_request(&request, request.length, NULL, NULL);
}
