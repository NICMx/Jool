#include "mode.h"
#include "netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool6)

static int pool4_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr;
	struct in_addr *addresses;
	__u16 addr_count;
	__u16 i;

	hdr = nlmsg_data(nlmsg_hdr(msg));
	addresses = (struct in_addr *) (hdr + 1);
	addr_count = (hdr->length - sizeof(*hdr)) / sizeof(*addresses);

	if (hdr->result_code != RESPONSE_SUCCESS) {
		print_code_msg(hdr, "IPv4 pool", NULL);
		return hdr->result_code;
	}

	if (addr_count == 0)
		printf("The pool is empty.\n");
	for (i = 0; i < addr_count; i++)
		printf("%s\n", inet_ntoa(addresses[i]));

	return 0;
}

error_t pool4_display(void)
{
	struct request_hdr request = {
			.length = sizeof(request),
			.mode = MODE_POOL4,
			.operation = OP_DISPLAY,
	};

	return netlink_single_request(&request, request.length, pool4_display_response);
}

static int pool4_add_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "IPv4 pool", "The address was added successfully.");
	return 0;
}

error_t pool4_add(struct in_addr *addr)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL4;
	hdr->operation = OP_ADD;
	payload->update.addr = *addr;

	return netlink_single_request(request, hdr->length, pool4_add_response);
}

static int pool4_remove_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "IPv4 pool", "The address was removed successfully.");
	return 0;
}

error_t pool4_remove(struct in_addr *addr)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_POOL4;
	hdr->operation = OP_REMOVE;
	payload->update.addr = *addr;

	return netlink_single_request(request, hdr->length, pool4_remove_response);
}
