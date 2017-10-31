#include "nat64/usr/pool4.h"

#include <errno.h>
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct display_args {
	unsigned int row_count;
	union request_pool4 *request;
	bool csv;
};

static int pool4_display_response(struct jool_response *response, void *arg)
{
	struct pool4_sample *samples = response->payload;
	unsigned int sample_count, i;
	struct display_args *args = arg;

	sample_count = response->payload_len / sizeof(*samples);

	for (i = 0; i < sample_count; i++) {
		if (args->csv)
			printf("%u,%s,%s,%u,%u,%u,%u\n", samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].range.addr),
					samples[i].range.ports.min,
					samples[i].range.ports.max,
					samples[i].iterations,
					samples[i].iterations_set);
		else
			printf("%10u  %5s  %15s  %8u  %8u  %10u  %16s\n",
					samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].range.addr),
					samples[i].range.ports.min,
					samples[i].range.ports.max,
					samples[i].iterations,
					samples[i].iterations_set ? "true" : "false");
	}

	args->row_count += sample_count;
	args->request->display.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

	return 0;
}

int pool4_display_proto(bool csv, l4_protocol proto, unsigned int *count)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, MODE_POOL4, OP_DISPLAY);
	payload->display.proto = proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.csv = csv;

	do {
		error = netlink_request(&request, sizeof(request),
				pool4_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	*count += args.row_count;
	return 0;
}

int pool4_display(display_flags flags)
{
	bool csv = flags & DF_CSV_FORMAT;
	int error;
	unsigned int count = 0;

	if (flags & DF_SHOW_HEADERS) {
		if (csv)
			printf("Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed\n");
		else
			printf("      Mark  Proto          Address  Port min  Port max  Iterations  Iterations fixed\n");
	}

	error = pool4_display_proto(csv, L4PROTO_TCP, &count);
	if (error)
		return error;
	error = pool4_display_proto(csv, L4PROTO_UDP, &count);
	if (error)
		return error;
	error = pool4_display_proto(csv, L4PROTO_ICMP, &count);
	if (error)
		return error;

	if (show_footer(flags)) {
		if (count > 0)
			log_info("  (Fetched %u samples.)", count);
		else
			log_info("  (empty)");
	}

	return 0;
}

int pool4_count(void)
{
	log_err("Sorry; --pool4 --count is not implemented anymore.");
	log_err("See https://github.com/NICMx/pool4-usage-analyzer");
	return -EINVAL;
}

int pool4_add(struct pool4_entry_usr *entry, bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	if (entry->range.prefix.len < 24 && !force) {
		printf("Warning: You're adding lots of addresses, which "
				"might defeat the whole point of NAT64 over "
				"SIIT.\n");
		printf("Also, and more or less as a consequence, addresses are "
				"stored in a linked list. Having too many "
				"addresses in pool4 sharing a mark is slow.\n");
		printf("Consider using SIIT instead.\n");
		printf("Will cancel the operation. Use --force to override "
				"this.\n");
		return -E2BIG;
	}

	init_request_hdr(hdr, MODE_POOL4, OP_ADD);
	payload->add = *entry;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool4_update(struct pool4_update *args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_UPDATE);
	payload->update = *args;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool4_rm(struct pool4_entry_usr *entry, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_REMOVE);
	payload->rm.entry = *entry;
	payload->rm.quick = quick;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool4_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, sizeof(request), NULL, NULL);
}
