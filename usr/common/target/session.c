#include "nat64/usr/session.h"

#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include "nat64/common/config.h"
#include "nat64/common/session.h"
#include "nat64/usr/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/dns.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

struct display_args {
	display_flags flags;
	unsigned int row_count;
	struct request_session *request;
};

char *tcp_state_to_string(tcp_state state)
{
	switch (state) {
	case ESTABLISHED:
		return "ESTABLISHED";
	case V4_INIT:
		return "V4_INIT";
	case V6_INIT:
		return "V6_INIT";
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

static void print_session_entry(struct session_entry_usr *entry,
		struct display_args *args)
{
	l4_protocol proto = args->request->l4_proto;

	if (args->flags & DF_CSV_FORMAT) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->src6, args->flags, ",", proto);
		printf(",");
		print_addr6(&entry->dst6, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",");
		print_addr4(&entry->src4, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",");
		print_addr4(&entry->dst4, args->flags, ",", proto);
		printf(",");
		print_time_csv(entry->dying_time);
		if (proto == L4PROTO_TCP)
			printf(",%s", tcp_state_to_string(entry->state));
		printf("\n");
	} else {
		if (proto == L4PROTO_TCP)
			printf("(%s) ", tcp_state_to_string(entry->state));

		printf("Expires in ");
		print_time_friendly(entry->dying_time);

		printf("Remote: ");
		print_addr4(&entry->dst4, args->flags, "#", proto);
		printf("\t");
		print_addr6(&entry->src6, args->flags, "#", proto);
		printf("\n");

		printf("Local: ");
		print_addr4(&entry->src4, DF_NUMERIC_HOSTNAME, "#", proto);
		printf("\t");
		print_addr6(&entry->dst6, DF_NUMERIC_HOSTNAME, "#", proto);
		printf("\n");

		printf("---------------------------------\n");
	}
}

static int session_display_response(struct jool_response *response, void *arg)
{
	struct session_entry_usr *entries = response->payload;
	struct display_args *args = arg;
	__u16 entry_count, i;

	entry_count = response->payload_len / sizeof(*entries);

	for (i = 0; i < entry_count; i++)
		print_session_entry(&entries[i], args);

	args->row_count += entry_count;
	args->request->display.offset_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct session_entry_usr *last = &entries[entry_count - 1];
		args->request->display.offset.src = last->src4;
		args->request->display.offset.dst = last->dst4;
	}

	return 0;
}

static bool display_table(char *iname, u_int8_t l4_proto, display_flags flags)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_session *payload = (struct request_session *)
			(request + HDR_LEN);
	struct display_args args;
	bool error;

	if (!(flags & DF_CSV_FORMAT)) {
		printf("%s:\n", l4proto_to_string(l4_proto));
		printf("---------------------------------\n");
	}

	init_request_hdr(hdr, MODE_SESSION, OP_DISPLAY);
	payload->l4_proto = l4_proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset.src, 0,
			sizeof(payload->display.offset.src));
	memset(&payload->display.offset.dst, 0,
			sizeof(payload->display.offset.dst));

	args.flags = flags;
	args.row_count = 0;
	args.request = payload;

	do {
		error = netlink_request(iname, request, sizeof(request),
				session_display_response, &args);
	} while (!error && args.request->display.offset_set);

	if (show_footer(flags) && !error) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)\n", args.row_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}

int session_display(char *iname, display_flags flags)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if ((flags & DF_SHOW_HEADERS) && (flags & DF_CSV_FORMAT)) {
		printf("Protocol,");
		printf("IPv6 Remote Address,IPv6 Remote L4-ID,");
		printf("IPv6 Local Address,IPv6 Local L4-ID,");
		printf("IPv4 Local Address,IPv4 Local L4-ID,");
		printf("IPv4 Remote Address,IPv4 Remote L4-ID,");
		printf("Expires in,State\n");
	}

	if (flags & DF_TCP)
		tcp_error = display_table(iname, L4PROTO_TCP, flags);
	if (flags & DF_UDP)
		udp_error = display_table(iname, L4PROTO_UDP, flags);
	if (flags & DF_ICMP)
		icmp_error = display_table(iname, L4PROTO_ICMP, flags);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int session_count_response(struct jool_response *response, void *arg)
{
	if (response->payload_len != sizeof(__u64)) {
		log_err("Jool's response is not the expected integer.");
		return -EINVAL;
	}

	printf("%llu\n", *((__u64 *)response->payload));
	return 0;
}

static bool display_single_count(char *iname, char *count_name,
		u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_session *payload = (struct request_session *)
			(request + HDR_LEN);

	init_request_hdr(hdr, MODE_SESSION, OP_COUNT);
	payload->l4_proto = l4_proto;

	return netlink_request(iname, request, sizeof(request),
			session_count_response, count_name);
}

int session_count(char *iname, display_flags flags)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (flags & DF_TCP)
		tcp_error = display_single_count(iname, "TCP", L4PROTO_TCP);
	if (flags & DF_UDP)
		udp_error = display_single_count(iname, "UDP", L4PROTO_UDP);
	if (flags & DF_ICMP)
		icmp_error = display_single_count(iname, "ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}
