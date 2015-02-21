#include "nat64/usr/rfc6791.h"
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


static int rfc6791_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct ipv4_prefix *prefix;
	__u16 addr_count, i;

	hdr = nlmsg_hdr(msg);
	prefix = nlmsg_data(hdr);
	addr_count = nlmsg_datalen(hdr) / sizeof(*prefix);

	for (i = 0; i < addr_count; i++)
		printf("%s/%u\n", inet_ntoa(prefix[i].address), prefix[i].len);

	*((int *) arg) += addr_count;
	return 0;
}

int rfc6791_display(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_RFC6791,
			.operation = OP_DISPLAY,
	};
	int row_count = 0;
	int error;

	error = netlink_request(&request, request.length, rfc6791_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			log_info("  (Fetched %u prefixes.)", row_count);
		else
			log_info("  (empty)");
	}

	return error;
}

static int rfc6791_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

int rfc6791_count(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_RFC6791,
			.operation = OP_COUNT,
	};
	return netlink_request(&request, request.length, rfc6791_count_response, NULL);
}

static int rfc6791_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was added successfully.");
	return 0;
}

int rfc6791_add(struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_RFC6791;
	hdr->operation = OP_ADD;
	payload->add.addrs = *addrs;

	return netlink_request(request, hdr->length, rfc6791_add_response, NULL);
}

static int rfc6791_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was removed successfully.");
	return 0;
}

int rfc6791_remove(struct ipv4_prefix *addrs, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_RFC6791;
	hdr->operation = OP_REMOVE;
	payload->remove.addrs = *addrs;
	payload->remove.quick = quick;

	return netlink_request(request, hdr->length, rfc6791_remove_response, NULL);
}

static int rfc6791_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("The RFC6791 pool was flushed successfully.");
	return 0;
}

int rfc6791_flush(bool quick)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_RFC6791,
			.operation = OP_FLUSH,
	};

	return netlink_request(&request, request.length, rfc6791_flush_response, NULL);
}
