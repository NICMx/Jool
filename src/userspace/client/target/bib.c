#include "bib.h"

#include <errno.h>

#include "dns.h"
#include "netlink.h"
#include "nl-protocol.h"
#include "str-utils.h"
#include "types.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_bib)


struct display_args {
	display_flags flags;
	unsigned int row_count;
	struct request_bib *request;
};

static void print_bib_entry(struct bib_entry_usr *entry,
		struct display_args *args)
{
	l4_protocol proto = entry->l4_proto;

	if (args->flags & DF_CSV_FORMAT) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->addr6, args->flags, ",", proto);
		printf(",");
		print_addr4(&entry->addr4, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",%u\n", entry->is_static);
	} else {
		printf("[%s] ", entry->is_static ? "Static" : "Dynamic");
		print_addr4(&entry->addr4, DF_NUMERIC_HOSTNAME, "#", proto);
		printf(" - ");
		print_addr6(&entry->addr6, args->flags, "#", proto);
		printf("\n");
	}
}

static int bib_display_response(struct jool_response *response, void *arg)
{
	struct bib_entry_usr *entries = response->payload;
	struct display_args *args = arg;
	unsigned int entry_count;
	unsigned int e;

	entry_count = response->payload_len / sizeof(*entries);

	for (e = 0; e < entry_count; e++)
		print_bib_entry(&entries[e], args);

	args->row_count += entry_count;
	args->request->display.addr4_set = response->hdr->pending_data;
	if (entry_count > 0)
		args->request->display.addr4 = entries[entry_count - 1].addr4;

	return 0;
}

static bool display_table(l4_protocol l4_proto, display_flags flags)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);
	struct display_args args;
	bool error;

	if (!(flags & DF_CSV_FORMAT))
		printf("%s:\n", l4proto_to_string(l4_proto));

	init_request_hdr(hdr, MODE_BIB, OP_DISPLAY);
	payload->l4_proto = l4_proto;
	payload->display.addr4_set = false;
	memset(&payload->display.addr4, 0, sizeof(payload->display.addr4));

	args.flags = flags;
	args.row_count = 0;
	args.request = payload;

	do {
		error = netlink_request(request, sizeof(request),
				bib_display_response, &args);
	} while (!error && payload->display.addr4_set);

	if (show_footer(flags) && !error) {
		if (args.row_count > 0)
			printf("  (Fetched %u entries.)\n", args.row_count);
		else
			printf("  (empty)\n");
	}

	return error;
}

/*
 * BTW: This thing is not thread-safe because of the address-to-string v4
 * function.
 */
int bib_display(display_flags flags)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if ((flags & DF_SHOW_HEADERS) && (flags & DF_CSV_FORMAT))
		printf("Protocol,IPv6 Address,IPv6 L4-ID,IPv4 Address,IPv4 L4-ID,Static?\n");

	if (flags & DF_TCP)
		tcp_error = display_table(L4PROTO_TCP, flags);
	if (flags & DF_UDP)
		udp_error = display_table(L4PROTO_UDP, flags);
	if (flags & DF_ICMP)
		icmp_error = display_table(L4PROTO_ICMP, flags);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int exec_request(display_flags flags,
		struct request_hdr *hdr, size_t request_len,
		struct request_bib *payload, jool_response_cb callback)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (flags & DF_TCP) {
		printf("TCP:\n");
		payload->l4_proto = L4PROTO_TCP;
		tcp_error = netlink_request(hdr, request_len, callback, NULL);
	}
	if (flags & DF_UDP) {
		printf("UDP:\n");
		payload->l4_proto = L4PROTO_UDP;
		udp_error = netlink_request(hdr, request_len, callback, NULL);
	}
	if (flags & DF_ICMP) {
		printf("ICMP:\n");
		payload->l4_proto = L4PROTO_ICMP;
		icmp_error = netlink_request(hdr, request_len, callback, NULL);
	}

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int bib_add_response(struct jool_response *response, void *arg)
{
	log_info("The BIB entry was added successfully.");
	return 0;
}

int bib_add(display_flags flags,
		struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BIB, OP_ADD);
	payload->add.addr6 = *addr6;
	payload->add.addr4 = *addr4;

	return exec_request(flags, hdr, sizeof(request), payload,
			bib_add_response);
}

static int bib_remove_response(struct jool_response *response, void *arg)
{
	log_info("The BIB entry was removed successfully.");
	return 0;
}

int bib_remove(display_flags flags,
		struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BIB, OP_REMOVE);
	if (addr6) {
		payload->rm.addr6_set = true;
		memcpy(&payload->rm.addr6, addr6, sizeof(*addr6));
	} else {
		payload->rm.addr6_set = false;
		memset(&payload->rm.addr6, 0, sizeof(payload->rm.addr6));
	}
	if (addr4) {
		payload->rm.addr4_set = true;
		memcpy(&payload->rm.addr4, addr4, sizeof(*addr4));
	} else {
		payload->rm.addr4_set = false;
		memset(&payload->rm.addr4, 0, sizeof(payload->rm.addr4));
	}

	return exec_request(flags, hdr, sizeof(request), payload,
			bib_remove_response);
}
