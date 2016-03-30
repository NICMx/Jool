#include "nat64/usr/bib.h"

#include <errno.h>
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/dns.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_bib)


struct display_params {
	bool numeric_hostname;
	bool csv_format;
	int row_count;
	struct request_bib *req_payload;
};

static int bib_display_response(struct jool_response *response, void *arg)
{
	struct bib_entry_usr *entries = response->payload;
	struct display_params *params = arg;
	__u16 entry_count, i;

	entry_count = response->payload_len / sizeof(*entries);

	if (params->csv_format) {
		for (i = 0; i < entry_count; i++) {
			printf("%s,", l4proto_to_string(entries[i].l4_proto));
			print_addr6(&entries[i].addr6, params->numeric_hostname, ",",
					entries[i].l4_proto);
			printf(",");
			print_addr4(&entries[i].addr4, true, ",", entries[i].l4_proto);
			printf(",%u\n", entries[i].is_static);
		}
	} else {
		for (i = 0; i < entry_count; i++) {
			printf("[%s] ", entries[i].is_static ? "Static" : "Dynamic");
			print_addr4(&entries[i].addr4, true, "#", entries[i].l4_proto);
			printf(" - ");
			print_addr6(&entries[i].addr6, params->numeric_hostname, "#",
					entries[i].l4_proto);
			printf("\n");
		}
	}

	params->row_count += entry_count;
	params->req_payload->display.addr4_set = response->hdr->pending_data;
	if (entry_count > 0)
		params->req_payload->display.addr4 = entries[entry_count - 1].addr4;
	return 0;
}

static bool display_single_table(l4_protocol l4_proto, bool numeric_hostname, bool csv_format)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);
	struct display_params params;
	bool error;

	if (!csv_format)
		printf("%s:\n", l4proto_to_string(l4_proto));

	init_request_hdr(hdr, MODE_BIB, OP_DISPLAY);
	payload->l4_proto = l4_proto;
	payload->display.addr4_set = false;
	memset(&payload->display.addr4, 0, sizeof(payload->display.addr4));

	params.numeric_hostname = numeric_hostname;
	params.csv_format = csv_format;
	params.row_count = 0;
	params.req_payload = payload;

	do {
		error = netlink_request(request, sizeof(request), bib_display_response, &params);
	} while (!error && payload->display.addr4_set);

	if (!csv_format && !error) {
		if (params.row_count > 0)
			printf("  (Fetched %u entries.)\n", params.row_count);
		else
			printf("  (empty)\n");
	}

	return error;
}

int bib_display(bool use_tcp, bool use_udp, bool use_icmp, bool numeric_hostname, bool csv_format)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (csv_format)
		printf("Protocol,IPv6 Address,IPv6 L4-ID,IPv4 Address,IPv4 L4-ID,Static?\n");

	if (use_tcp)
		tcp_error = display_single_table(L4PROTO_TCP, numeric_hostname, csv_format);
	if (use_udp)
		udp_error = display_single_table(L4PROTO_UDP, numeric_hostname, csv_format);
	if (use_icmp)
		icmp_error = display_single_table(L4PROTO_ICMP, numeric_hostname, csv_format);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int bib_count_response(struct jool_response *response, void *arg)
{
	if (response->payload_len != sizeof(__u64)) {
		log_err("Jool's response is not the expected integer.");
		return -EINVAL;
	}

	printf("%llu\n", *((__u64 *)response->payload));
	return 0;
}

static bool display_single_count(char *count_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	printf("%s: ", count_name);

	init_request_hdr(hdr, MODE_BIB, OP_COUNT);
	payload->l4_proto = l4_proto;

	return netlink_request(request, sizeof(request), bib_count_response, NULL);
}

int bib_count(bool use_tcp, bool use_udp, bool use_icmp)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_count("TCP", L4PROTO_TCP);
	if (use_udp)
		udp_error = display_single_count("UDP", L4PROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_count("ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int exec_request(bool use_tcp, bool use_udp, bool use_icmp,
		struct request_hdr *hdr, size_t request_len,
		struct request_bib *payload, jool_response_cb callback)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp) {
		printf("TCP:\n");
		payload->l4_proto = L4PROTO_TCP;
		tcp_error = netlink_request(hdr, request_len, callback, NULL);
	}
	if (use_udp) {
		printf("UDP:\n");
		payload->l4_proto = L4PROTO_UDP;
		udp_error = netlink_request(hdr, request_len, callback, NULL);
	}
	if (use_icmp) {
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

int bib_add(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);

	init_request_hdr(hdr, MODE_BIB, OP_ADD);
	payload->add.addr6 = *addr6;
	payload->add.addr4 = *addr4;

	return exec_request(use_tcp, use_udp, use_icmp,
			hdr, sizeof(request),
			payload, bib_add_response);
}

static int bib_remove_response(struct jool_response *response, void *arg)
{
	log_info("The BIB entry was removed successfully.");
	return 0;
}

int bib_remove(bool use_tcp, bool use_udp, bool use_icmp,
		struct ipv6_transport_addr *addr6,
		struct ipv4_transport_addr *addr4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);

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

	return exec_request(use_tcp, use_udp, use_icmp,
			hdr, sizeof(request),
			payload, bib_remove_response);
}
