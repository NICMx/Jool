#include "nat64/usr/customer.h"

#include <errno.h>
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_customer)


struct display_args {
	display_flags flags;
	unsigned int row_count;
	union request_customer *request;
};

static void print_customer_entry(struct customer_entry_usr *entry, char *separator)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->prefix6.address, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->prefix4.address);
	printf("%s/%u/%u", ipv6_str, entry->prefix6.len, entry->groups6_size_len);
	printf("%s", separator);
	printf("%s/%u/%u", ipv4_str, entry->prefix4.len, entry->ports_division_len);
	printf("%s", separator);
	printf("%u", entry->ports.min);
	printf("%s", separator);
	printf("%u", entry->ports.max);
	printf("\n");
}

static int customer_display_response(struct jool_response *response, void *arg)
{
	struct customer_entry_usr *entry = response->payload;
	struct display_args *args = arg;

	if (response->payload_len <= 0) {
		log_info("  (empty)");
		return 0;
	}

	if (args->flags & DF_CSV_FORMAT) {
		print_customer_entry(entry, ",");
	} else {
		print_customer_entry(entry, " - ");
	}

	return 0;
}

int customer_display(display_flags flags)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_customer *payload = (union request_customer *)(request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, MODE_CUSTOMER, OP_DISPLAY);
	args.flags = flags;
	args.row_count = 0;
	args.request = payload;

	if ((flags & DF_SHOW_HEADERS) && (flags & DF_CSV_FORMAT))
		printf("IPv6 Prefix,IPv4 Prefix,Ports\n");

	error = netlink_request(request, sizeof(request),
			customer_display_response, &args);
	if (error)
		return error;


	return 0;
}

int customer_add(struct customer_entry_usr *entry)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_customer *payload = (union request_customer *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_CUSTOMER, OP_ADD);
	payload->add = *entry;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int customer_rm(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_customer *payload = (union request_customer *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_CUSTOMER, OP_REMOVE);
	payload->rm.quick = quick;

	return netlink_request(request, sizeof(request), NULL, NULL);
}

int customer_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_customer *payload = (union request_customer *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_CUSTOMER, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, sizeof(request), NULL, NULL);
}
