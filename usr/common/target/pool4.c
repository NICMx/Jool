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
	display_flags flags;

	struct {
		bool initialized;
		__u32 mark;
		__u8 proto;
	} last;
};

static void display_sample_csv(struct pool4_sample *sample,
		struct display_args *args)
{
	printf("%u,%s,%s,%u,%u,%u,%u\n", sample->mark,
			l4proto_to_string(sample->proto),
			inet_ntoa(sample->range.addr),
			sample->range.ports.min,
			sample->range.ports.max,
			sample->iterations,
			sample->iterations_set);
}

static bool print_common_values(struct pool4_sample *sample,
		struct display_args *args)
{
	if (!args->last.initialized)
		return true;
	return sample->mark != args->last.mark
			|| sample->proto != args->last.proto;
}

static void print_table_divisor(void)
{
	/*
	 * Lol, dude. Maybe there's some console table manager library out there
	 * that we should be using.
	 */
	printf("+------------+-------+--------------------+-----------------+----------+----------+\n");
}

static void display_sample_normal(struct pool4_sample *sample,
		struct display_args *args)
{
	if (print_common_values(sample, args)) {
		print_table_divisor();
		printf("| %10u | %5s | %10u (%5s) | %15s | %8u | %8u |\n",
				sample->mark,
				l4proto_to_string(sample->proto),
				sample->iterations,
				sample->iterations_set ? "fixed" : "auto",
				inet_ntoa(sample->range.addr),
				sample->range.ports.min,
				sample->range.ports.max);
	} else {
		printf("| %10s | %5s | %10s  %5s  | %15s | %8u | %8u |\n",
				"",
				"",
				"",
				"",
				inet_ntoa(sample->range.addr),
				sample->range.ports.min,
				sample->range.ports.max);
	}

	args->last.initialized = true;
	args->last.mark = sample->mark;
	args->last.proto = sample->proto;
}

static int pool4_display_response(struct jool_response *response, void *arg)
{
	struct pool4_sample *samples = response->payload;
	unsigned int sample_count, i;
	struct display_args *args = arg;

	sample_count = response->payload_len / sizeof(*samples);

	for (i = 0; i < sample_count; i++) {
		if (args->flags & DF_CSV_FORMAT)
			display_sample_csv(&samples[i], args);
		else
			display_sample_normal(&samples[i], args);
	}

	args->row_count += sample_count;
	args->request->display.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

	return 0;
}

int pool4_display_proto(display_flags flags, l4_protocol proto, unsigned int *count)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, MODE_POOL4, OP_DISPLAY);
	payload->display.proto = proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.flags = flags;
	args.last.initialized = false;
	args.last.mark = 0;
	args.last.proto = 0;

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
	unsigned int count = 0;
	int error;

	if (flags & DF_SHOW_HEADERS) {
		if (flags & DF_CSV_FORMAT)
			printf("Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed\n");
		else {
			print_table_divisor();
			printf("|       Mark | Proto |     Max iterations |         Address | Port min | Port max |\n");
		}
	}

	error = pool4_display_proto(flags, L4PROTO_TCP, &count);
	if (error)
		return error;
	error = pool4_display_proto(flags, L4PROTO_UDP, &count);
	if (error)
		return error;
	error = pool4_display_proto(flags, L4PROTO_ICMP, &count);
	if (error)
		return error;

	if (!(flags & DF_CSV_FORMAT))
		print_table_divisor();

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
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

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
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_UPDATE);
	payload->update = *args;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool4_rm(struct pool4_entry_usr *entry, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_REMOVE);
	payload->rm.entry = *entry;
	payload->rm.quick = quick;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool4_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, sizeof(request), NULL, NULL);
}
