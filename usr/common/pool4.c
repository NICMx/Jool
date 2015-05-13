#include "nat64/usr/pool4.h"
#include "nat64/common/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct display_args {
	unsigned int row_count;
	union request_pool4 *request;
};

static int pool4_display_response(struct nl_msg *response, void *arg)
{
	struct nlmsghdr *hdr;
	struct ipv4_prefix *prefixes;
	unsigned int prefix_count, i;
	struct display_args *args = arg;

	hdr = nlmsg_hdr(response);
	prefixes = nlmsg_data(hdr);
	prefix_count = nlmsg_datalen(hdr) / sizeof(*prefixes);

	for (i = 0; i < prefix_count; i++)
		printf("%s/%u\n", inet_ntoa(prefixes[i].address), prefixes[i].len);

	args->row_count += prefix_count;
	args->request->display.prefix_set = hdr->nlmsg_flags & NLM_F_MULTI;
	if (prefix_count > 0)
		args->request->display.prefix = prefixes[prefix_count - 1];
	return 0;
}

int pool4_display(enum config_mode mode)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, sizeof(request), mode, OP_DISPLAY);
	payload->display.prefix_set = false;
	memset(&payload->display.prefix, 0, sizeof(payload->display.prefix));
	args.row_count = 0;
	args.request = payload;

	do {
		error = netlink_request(&request, hdr->length, pool4_display_response, &args);
	} while (!error && args.request->display.prefix_set);

	if (!error) {
		if (args.row_count > 0)
			log_info("  (Fetched %u prefixes.)", args.row_count);
		else
			log_info("  (empty)");
	}

	return error;
}

static int pool4_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

int pool4_count(enum config_mode mode)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), mode, OP_COUNT);
	return netlink_request(&request, request.length, pool4_count_response, NULL);
}

static int pool4_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was added successfully.");
	return 0;
}

int pool4_add(enum config_mode mode, struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_ADD);
	payload->add.addrs = *addrs;

	return netlink_request(request, hdr->length, pool4_add_response, NULL);
}

static int pool4_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The prefix was removed successfully.");
	return 0;
}

int pool4_remove(enum config_mode mode, struct ipv4_prefix *addrs, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_REMOVE);
	payload->rm.addrs = *addrs;
	payload->rm.quick = quick;

	return netlink_request(request, hdr->length, pool4_remove_response, NULL);
}

static int pool4_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("The pool was flushed successfully.");
	return 0;
}

int pool4_flush(enum config_mode mode, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, hdr->length, pool4_flush_response, NULL);
}
