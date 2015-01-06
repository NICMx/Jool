#include "nat64/usr/pool4.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


static int pool4_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct in_addr *addresses;
	__u16 addr_count, i;

	hdr = nlmsg_hdr(msg);
	addresses = nlmsg_data(hdr);
	addr_count = nlmsg_datalen(hdr) / sizeof(*addresses);

	for (i = 0; i < addr_count; i++)
		printf("%s\n", inet_ntoa(addresses[i]));

	*((int *) arg) += addr_count;
	return 0;
}

int pool4_display(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL4,
			.operation = OP_DISPLAY,
	};
	int row_count = 0;
	int error;

	error = netlink_request(&request, request.length, pool4_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			log_info("  (Fetched %u addresses.)", row_count);
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

int pool4_count(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL4,
			.operation = OP_COUNT,
	};
	return netlink_request(&request, request.length, pool4_count_response, NULL);
}

static int pool4_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The address was added successfully.");
	return 0;
}

int pool4_add(struct in_addr *addr, unsigned char *mask)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL4;
	hdr->operation = OP_ADD;
	payload->add.addr = *addr;
	payload->add.maskbits = *mask;

	return netlink_request(request, hdr->length, pool4_add_response, NULL);
}

static int pool4_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The address was removed successfully.");
	return 0;
}

int pool4_remove(struct in_addr *addr,unsigned char *mask, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL4;
	hdr->operation = OP_REMOVE;
	payload->remove.addr = *addr;
	payload->remove.maskbits = *mask;
	payload->remove.quick = quick;

	return netlink_request(request, hdr->length, pool4_remove_response, NULL);
}

static int pool4_flush_response(struct nl_msg *msg, void *arg)
{
	log_info("The IPv4 pool was flushed successfully.");
	return 0;
}

int pool4_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL4;
	hdr->operation = OP_FLUSH;
	payload->flush.quick = quick;

	return netlink_request(&request, hdr->length, pool4_flush_response, NULL);
}
