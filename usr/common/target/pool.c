#include "nat64/usr/pool.h"

#include <errno.h>
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool)


struct display_args {
	unsigned int row_count;
	union request_pool *request;
	bool csv;
};

static int pool_display_response(struct jool_response *response, void *arg)
{
	struct ipv4_prefix *prefixes = response->payload;
	unsigned int prefix_count, i;
	struct display_args *args = arg;

	prefix_count = response->payload_len / sizeof(*prefixes);

	if (args->row_count == 0 && args->csv)
		printf("Prefix\n");

	for (i = 0; i < prefix_count; i++) {
		printf("%s/%u\n", inet_ntoa(prefixes[i].address),
				prefixes[i].len);
	}

	args->row_count += prefix_count;
	args->request->display.offset_set = response->hdr->pending_data;
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

	init_request_hdr(hdr, mode, OP_DISPLAY);
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.csv = csv;

	do {
		error = netlink_request(&request, sizeof(request), pool_display_response, &args);
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

static int count_response(struct jool_response *response, void *arg)
{
	if (response->payload_len != sizeof(__u64)) {
		log_err("Jool's response is not the expected integer.");
		return -EINVAL;
	}

	printf("%llu\n", *((__u64 *)response->payload));
	return 0;
}

int pool_count(enum config_mode mode)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	init_request_hdr(hdr, mode, OP_COUNT);
	return netlink_request(request, sizeof(request), count_response, NULL);
}

int pool_add(enum config_mode mode, struct ipv4_prefix *addrs, bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool *payload = (union request_pool *) (request + HDR_LEN);

	init_request_hdr(hdr, mode, OP_ADD);
	payload->add.addrs = *addrs;
	payload->add.force = force;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool_rm(enum config_mode mode, struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool *payload = (union request_pool *) (request + HDR_LEN);

	init_request_hdr(hdr, mode, OP_REMOVE);
	payload->rm.addrs = *addrs;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int pool_flush(enum config_mode mode)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;

	init_request_hdr(hdr, mode, OP_FLUSH);

	return netlink_request(&request, sizeof(request), NULL, NULL);
}
