#include "nat64/mode.h"
#include "nat64/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool6)

static int pool6_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr;
	struct ipv6_prefix *prefixes;
	__u16 prefix_count;
	__u16 i;
	char addr_str[INET6_ADDRSTRLEN];

	hdr = nlmsg_data(nlmsg_hdr(msg));
	prefixes = (struct ipv6_prefix *) (hdr + 1);
	prefix_count = (hdr->length - sizeof(*hdr)) / sizeof(*prefixes);

	if (hdr->result_code != RESPONSE_SUCCESS) {
		print_code_msg(hdr, "IPv6 pool", NULL);
		return hdr->result_code;
	}

	if (prefix_count == 0)
		printf("The pool is empty.\n");
	for (i = 0; i < prefix_count; i++) {
		inet_ntop(AF_INET6, &prefixes[i].address, addr_str, INET6_ADDRSTRLEN);
		printf("%s/%u\n", addr_str, prefixes[i].len);
	}

	return 0;
}

error_t pool6_display(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL6,
			.operation = OP_DISPLAY,
	};

	return netlink_single_request(&request, request.length, pool6_display_response);
}

static int pool6_add_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "IPv6 pool", "The prefix was added successfully.");
	return 0;
}

error_t pool6_add(struct ipv6_prefix *prefix)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool6 *payload = (union request_pool6 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL6;
	hdr->operation = OP_ADD;
	payload->update.prefix = *prefix;

	return netlink_single_request(request, hdr->length, pool6_add_response);
}

static int pool6_remove_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "IPv6 pool", "The prefix was removed successfully.");
	return 0;
}

error_t pool6_remove(struct ipv6_prefix *prefix)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool6 *payload = (union request_pool6 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL6;
	hdr->operation = OP_REMOVE;
	payload->update.prefix = *prefix;

	return netlink_single_request(request, hdr->length, pool6_remove_response);
}
