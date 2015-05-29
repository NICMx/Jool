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
	struct pool4_sample *samples;
	unsigned int sample_count, i;
	struct display_args *args = arg;

	hdr = nlmsg_hdr(response);
	samples = nlmsg_data(hdr);
	sample_count = nlmsg_datalen(hdr) / sizeof(*samples);

	for (i = 0; i < sample_count; i++) {
		printf("%u\t%s\t%u-%u\n", samples[i].mark,
				inet_ntoa(samples[i].addr),
				samples[i].range.min,
				samples[i].range.max);
	}

	args->row_count += sample_count;
	args->request->display.offset_set = hdr->nlmsg_flags & NLM_F_MULTI;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

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
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;

	do {
		error = netlink_request(&request, hdr->length, pool4_display_response, &args);
	} while (!error && args.request->display.offset_set);

	if (!error) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)", args.row_count);
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

int pool4_add(enum config_mode mode, __u32 mark, struct ipv4_prefix *addrs,
		struct port_range *ports)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_ADD);
	payload->add.mark = mark;
	payload->add.addrs = *addrs;
	payload->add.ports = *ports;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_remove(enum config_mode mode, __u32 mark, struct ipv4_prefix *addrs,
		struct port_range *ports, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_REMOVE);
	payload->rm.mark = mark;
	payload->rm.addrs = *addrs;
	payload->rm.ports = *ports;
	payload->rm.quick = quick;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_flush(enum config_mode mode, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, hdr->length, NULL, NULL);
}
