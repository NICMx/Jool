#include "nat64/usr/session.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
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
	int row_count;
	struct request_session *req_payload;
};

static int session_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct session_entry_us *entries;
	struct display_params *params = arg;
	__u16 entry_count, i;

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		struct session_entry_us *entry = &entries[i];

		printf("Expires in ");
		print_time(entry->dying_time);

		printf("Remote: ");
		print_ipv4_tuple(&entry->ipv4.remote, params->numeric_hostname);

		printf("\t");
		print_ipv6_tuple(&entry->ipv6.remote, params->numeric_hostname);
		printf("\n");

		printf("Local: ");
		print_ipv4_tuple(&entry->ipv4.local, true);

		printf("\t");
		print_ipv6_tuple(&entry->ipv6.local, true);
		printf("\n");

		printf("---------------------------------\n");
	}

	params->row_count += entry_count;

	if (hdr->nlmsg_flags == NLM_F_MULTI) {
		params->req_payload->iterate = true;
		params->req_payload->ipv4.address = *(&entries[entry_count - 1].ipv4.local.address);
		params->req_payload->ipv4.l4_id = *(&entries[entry_count - 1].ipv4.local.l4_id);
	} else {
		params->req_payload->iterate = false;
	}

	return 0;
}

static bool display_single_table(char *table_name, u_int8_t l4_proto, bool numeric_hostname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);
	struct display_params params;
	bool error;

	printf("%s:\n", table_name);
	printf("---------------------------------\n");

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_DISPLAY;
	payload->l4_proto = l4_proto;
	payload->iterate = false;
	memset(&payload->ipv4, 0, sizeof(payload->ipv4));

	params.numeric_hostname = numeric_hostname;
	params.row_count = 0;
	params.req_payload = payload;

	do {
		error = netlink_request(request, hdr->length, session_display_response, &params);
		if (error)
			break;
	} while (params.req_payload->iterate);

	if (!error) {
		if (params.row_count > 0)
			log_info("  (Fetched %u entries.)\n", params.row_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}

int session_display(bool use_tcp, bool use_udp, bool use_icmp, bool numeric_hostname)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_table("TCP", L4PROTO_TCP, numeric_hostname);
	if (use_udp)
		udp_error = display_single_table("UDP", L4PROTO_UDP, numeric_hostname);
	if (use_icmp)
		icmp_error = display_single_table("ICMP", L4PROTO_ICMP, numeric_hostname);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int session_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

static bool display_single_count(char *count_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	printf("%s: ", count_name);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_COUNT;
	payload->l4_proto = l4_proto;

	return netlink_request(request, hdr->length, session_count_response, NULL);
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
