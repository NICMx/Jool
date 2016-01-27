#include "nat64/usr/session.h"
#include "nat64/common/config.h"
#include "nat64/common/session.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/dns.h"
#include <errno.h>
#include <time.h>
#include <sys/socket.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

struct display_params {
	bool numeric_hostname;
	bool csv_format;
	int row_count;
	struct request_session *req_payload;
};

char *tcp_state_to_string(enum tcp_state state)
{
	switch (state) {
	case CLOSED:
		return "CLOSED";
	case V4_INIT:
		return "V4_INIT";
	case V6_INIT:
		return "V6_INIT";
	case ESTABLISHED:
		return "ESTABLISHED";
	case V4_FIN_RCV:
		return "V4_FIN_RCV";
	case V6_FIN_RCV:
		return "V6_FIN_RCV";
	case V4_FIN_V6_FIN_RCV:
		return "V4_FIN_V6_FIN_RCV";
	case TRANS:
		return "TRANS";
	}

	return "UNKNOWN";
}

static int session_display_response(struct nl_core_buffer *buffer, void *arg)
{
	struct session_entry_usr *entries;
	struct display_params *params = arg;
	__u16 entry_count, i;


	entries = netlink_get_data(buffer);
	entry_count = buffer->len / sizeof(*entries);

	if (params->csv_format) {
		for (i = 0; i < entry_count; i++) {
			struct session_entry_usr *entry = &entries[i];

			printf("%s,", l4proto_to_string(params->req_payload->l4_proto));
			print_addr6(&entry->remote6, params->numeric_hostname, ",",
					params->req_payload->l4_proto);
			printf(",");
			print_addr6(&entry->local6, true, ",", params->req_payload->l4_proto);
			printf(",");
			print_addr4(&entry->local4, true, ",", params->req_payload->l4_proto);
			printf(",");
			print_addr4(&entry->remote4, params->numeric_hostname, ",",
					params->req_payload->l4_proto);
			printf(",");
			print_time_csv(entry->dying_time);
			if (params->req_payload->l4_proto == L4PROTO_TCP)
				printf(",%s", tcp_state_to_string(entry->state));
			printf("\n");
		}
	} else {
		for (i = 0; i < entry_count; i++) {
			struct session_entry_usr *entry = &entries[i];

			if (params->req_payload->l4_proto == L4PROTO_TCP)
				printf("(%s) ", tcp_state_to_string(entry->state));

			printf("Expires in ");
			print_time_friendly(entry->dying_time);

			printf("Remote: ");
			print_addr4(&entry->remote4, params->numeric_hostname, "#",
					params->req_payload->l4_proto);

			printf("\t");
			print_addr6(&entry->remote6, params->numeric_hostname, "#",
					params->req_payload->l4_proto);
			printf("\n");

			printf("Local: ");
			print_addr4(&entry->local4, true, "#", params->req_payload->l4_proto);

			printf("\t");
			print_addr6(&entry->local6, true, "#", params->req_payload->l4_proto);
			printf("\n");

			printf("---------------------------------\n");
		}
	}

	params->row_count += entry_count;
	params->req_payload->display.connection_set = buffer->pending_data;
	if (entry_count > 0) {
		params->req_payload->display.remote4 = entries[entry_count - 1].remote4;
		params->req_payload->display.local4 = entries[entry_count - 1].local4;
	}
	return 0;
}

static bool display_single_table(u_int8_t l4_proto, bool numeric_hostname, bool csv_format)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);
	struct display_params params;
	bool error;

	if (!csv_format) {
		printf("%s:\n", l4proto_to_string(l4_proto));
		printf("---------------------------------\n");
	}

	init_request_hdr(hdr, sizeof(request), MODE_SESSION, OP_DISPLAY);
	payload->l4_proto = l4_proto;
	payload->display.connection_set = false;
	memset(&payload->display.remote4, 0, sizeof(payload->display.remote4));
	memset(&payload->display.local4, 0, sizeof(payload->display.local4));

	params.numeric_hostname = numeric_hostname;
	params.csv_format = csv_format;
	params.row_count = 0;
	params.req_payload = payload;

	do {
		error = netlink_request(request, hdr->length, session_display_response, &params);
	} while (!error && params.req_payload->display.connection_set);

	if (!csv_format && !error) {
		if (params.row_count > 0)
			log_info("  (Fetched %u entries.)\n", params.row_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}

int session_display(bool use_tcp, bool use_udp, bool use_icmp, bool numeric_hostname,
		bool csv_format)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (csv_format) {
		printf("Protocol,");
		printf("IPv6 Remote Address,IPv6 Remote L4-ID,IPv6 Local Address,IPv6 Local L4-ID,");
		printf("IPv4 Local Address,IPv4 Local L4-ID,IPv4 Remote Address,IPv4 Remote L4-ID,");
		printf("Expires in,State");
		printf("\n");
	}

	if (use_tcp)
		tcp_error = display_single_table(L4PROTO_TCP, numeric_hostname, csv_format);
	if (use_udp)
		udp_error = display_single_table(L4PROTO_UDP, numeric_hostname, csv_format);
	if (use_icmp)
		icmp_error = display_single_table(L4PROTO_ICMP, numeric_hostname, csv_format);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int session_count_response(struct nl_core_buffer *buffer, void *arg)
{
	__u64 *conf = netlink_get_data(buffer);
	printf("%s: %llu\n", (char *)arg, *conf);
	return 0;
}

static bool display_single_count(char *count_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	//printf("%s: ", count_name);

	init_request_hdr(hdr, sizeof(request), MODE_SESSION, OP_COUNT);
	payload->l4_proto = l4_proto;

	return netlink_request(request, hdr->length, session_count_response, count_name);
}

int session_count(bool use_tcp, bool use_udp, bool use_icmp)
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
