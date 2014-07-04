#include "nat64/usr/pool6.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool6)


static int pool6_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct ipv6_prefix *prefixes;
	int pref_count, i;
	char addr_str[INET6_ADDRSTRLEN];

	hdr = nlmsg_hdr(msg);
	prefixes = nlmsg_data(hdr);
	pref_count = nlmsg_datalen(hdr) / sizeof(*prefixes);

	for (i = 0; i < pref_count; i++) {
		inet_ntop(AF_INET6, &prefixes[i].address, addr_str, INET6_ADDRSTRLEN);
		printf("%s/%u\n", addr_str, prefixes[i].len);
	}

	*((int *) arg) += pref_count;
	return 0;
}

int pool6_display(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL6,
			.operation = OP_DISPLAY,
	};
	int row_count = 0;
	int error;

	error = netlink_request(&request, request.length, pool6_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			log_info("  (Fetched %u prefixes.)", row_count);
		else
			log_info("  (empty)");
	}

	return error;
}

static int pool6_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

int pool6_count(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL6,
			.operation = OP_COUNT,
	};
	return netlink_request(&request, request.length, pool6_count_response, NULL);
}

static int pool6_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was added successfully.");
	return 0;
}

int pool6_add(struct ipv6_prefix *prefix)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool6 *payload = (union request_pool6 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL6;
	hdr->operation = OP_ADD;
	payload->update.prefix = *prefix;

	return netlink_request(request, hdr->length, pool6_add_response, NULL);
}

static int pool6_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was removed successfully.");
	return 0;
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool6 *payload = (union request_pool6 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL6;
	hdr->operation = OP_REMOVE;
	payload->update.prefix = *prefix;

	return netlink_request(request, hdr->length, pool6_remove_response, NULL);
}

static int pool6_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("The IPv6 pool was flushed successfully.");
	return 0;
}

int pool6_flush(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL6,
			.operation = OP_FLUSH,
	};
	return netlink_request(&request, request.length, pool6_flush_response, NULL);
}
