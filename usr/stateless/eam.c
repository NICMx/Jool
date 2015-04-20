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

static void print_eam_entry_usr(struct eam_entry_usr *entry, char *separator)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->pref6.address, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->pref4.address);
	printf("%s/%u", ipv6_str, entry->pref6.len);
	printf("%s", separator);
	printf("%s/%u", ipv4_str, entry->pref4.len);
	printf("\n");
}

static int eam_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct eam_entry_usr *entries;
	struct display_params *params = arg;
	__u16 entry_count, i;

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	if (params->csv_format) {
		for (i = 0; i < entry_count; i++) {
			print_eam_entry_usr(&entries[i], ",");
		}
	} else {
		for (i = 0; i < entry_count; i++) {
			print_eam_entry_usr(&entries[i], " - ");
		}
	}

	params->row_count += entry_count;
	params->req_payload->display.prefix4_set = hdr->nlmsg_flags & NLM_F_MULTI;
	if (entry_count > 0)
		params->req_payload->display.prefix4 = entries[entry_count - 1].pref4;
	return 0;
}

int eam_display(bool csv_format)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);
	struct display_params params;
	int error;

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_DISPLAY);
	payload->display.prefix4_set = false;
	memset(&payload->display.prefix4, 0, sizeof(payload->display.prefix4));
	params.csv_format = csv_format;
	params.row_count = 0;
	params.req_payload = payload;

	if (csv_format)
		printf("IPv6 Prefix,IPv4 Prefix\n");

	do {
		error = netlink_request(request, hdr->length, eam_display_response, &params);
	} while (!error && payload->display.prefix4_set);

	if (!csv_format && !error) {
		if (params.row_count > 0)
			printf("  (Fetched %u entries.)\n", params.row_count);
		else
			printf("  (empty)\n");
	}

	return error;
}

static int eam_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

int eam_count(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_EAMT, OP_COUNT);
	return netlink_request(&request, request.length, eam_count_response, NULL);
}

static int eam_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The EAM entry was added successfully.");
	return 0;
}

int eam_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_ADD);
	payload->add.prefix4 = *prefix4;
	payload->add.prefix6 = *prefix6;

	return netlink_request(request, hdr->length, eam_add_response, NULL);
}

static int eam_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The EAM entry was removed successfully.");
	return 0;
}

int eam_remove(bool pref6_set, struct ipv6_prefix *prefix6, bool pref4_set,
		struct ipv4_prefix *prefix4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_eamt *payload = (union request_eamt *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_EAMT, OP_REMOVE);
	payload->remove.prefix4_set = pref4_set;
	payload->remove.prefix4 = *prefix4;
	payload->remove.prefix6_set = pref6_set;
	payload->remove.prefix6 = *prefix6;

	return netlink_request(request, hdr->length, eam_remove_response, NULL);
}

static int eam_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("The EAM table was flushed successfully.");
	return 0;
}

int eam_flush()
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_EAMT, OP_FLUSH);
	return netlink_request(&request, request.length, eam_flush_response, NULL);
}
