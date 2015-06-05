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

int pool4_display(void)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_DISPLAY);
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
	struct response_pool4_count *response = nlmsg_data(nlmsg_hdr(msg));

	printf("tables: %u\n", response->tables);
	printf("samples: %llu\n", response->samples);
	printf("transport addresses: %llu\n", response->taddrs);

	return 0;
}

int pool4_count(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_POOL4, OP_COUNT);
	return netlink_request(&request, request.length, pool4_count_response, NULL);
}

int pool4_add(__u32 mark, struct ipv4_prefix *addrs, struct port_range *ports)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_ADD);
	payload->add.mark = mark;
	payload->add.addrs = *addrs;
	payload->add.ports = *ports;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_rm(__u32 mark, struct ipv4_prefix *addrs, struct port_range *ports,
		bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_REMOVE);
	payload->rm.mark = mark;
	payload->rm.addrs = *addrs;
	payload->rm.ports = *ports;
	payload->rm.quick = quick;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, hdr->length, NULL, NULL);
}
