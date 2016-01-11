#include "nat64/usr/pool.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool)


struct display_args {
	unsigned int row_count;
	union request_pool *request;
	bool csv;
};

static int pool_display_response(struct nl_core_buffer *buffer, void *arg)
{
	struct ipv4_prefix *prefixes;
	unsigned int prefix_count, i;
	struct display_args *args = arg;

	prefixes = netlink_get_data(buffer);
	prefix_count = buffer->len / sizeof(*prefixes);

	if (args->row_count == 0 && args->csv)
		printf("Prefix\n");

	for (i = 0; i < prefix_count; i++) {
		printf("%s/%u\n", inet_ntoa(prefixes[i].address),
				prefixes[i].len);
	}

	args->row_count += prefix_count;
	args->request->display.offset_set = buffer->pending_data;
	if (prefix_count > 0)
		args->request->display.offset = prefixes[prefix_count - 1];

	return 0;
}

int pool_display(enum config_mode mode, bool csv)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool *payload = (union request_pool *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, sizeof(request), mode, OP_DISPLAY);
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.csv = csv;

	do {
		error = netlink_request(&request, hdr->length, pool_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	if (!csv) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)", args.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static int pool_count_response(struct nl_core_buffer *buffer, void *arg)
{
	__u64 *count = netlink_get_data(buffer);
	printf("%llu\n", *count);
	return 0;
}

int pool_count(enum config_mode mode)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), mode, OP_COUNT);
	return netlink_request(&request, request.length, pool_count_response, NULL);
}

int pool_add(enum config_mode mode, struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool *payload = (union request_pool *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_ADD);
	payload->add.addrs = *addrs;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool_rm(enum config_mode mode, struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool *payload = (union request_pool *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), mode, OP_REMOVE);
	payload->rm.addrs = *addrs;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool_flush(enum config_mode mode)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;

	init_request_hdr(hdr, sizeof(request), mode, OP_FLUSH);

	return netlink_request(&request, hdr->length, NULL, NULL);
}
