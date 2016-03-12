#ifdef BENCHMARK

#include "nat64/usr/log_time.h"

#include <errno.h>
#include <time.h>
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_logtime)

struct display_params {
	struct request_logtime *req_payload;
	int row_count;
};

static int logtime_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct logtime_entry_usr *entries;
	struct display_params *params = arg;
	const char *l3_proto_out, *l4_proto;
	char *l3_proto_in;
	__u16 entry_count, i;

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	if (params->req_payload->l3_proto == L3PROTO_IPV4) {
		l3_proto_in = "IPv6";
	} else {
		l3_proto_in = "IPv4";
	}
	l3_proto_out = l3proto_to_string(params->req_payload->l3_proto);
	l4_proto = l4proto_to_string(params->req_payload->l4_proto);

	for (i = 0; i < entry_count; i++) {
		printf ("%s->%s,", l3_proto_in, l3_proto_out);
		printf ("%s,", l4_proto);
		printf ("%ld,%ld\n", entries[i].time.tv_sec, entries[i].time.tv_nsec);
	}

	params->row_count += entry_count;

	if (hdr->nlmsg_flags & NLM_F_MULTI) {
		params->req_payload->display.iterate = true;
	} else {
		params->req_payload->display.iterate = false;
	}
	return 0;
}


static bool display_single_db(l3_protocol l3_proto, l4_protocol l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_logtime *payload = (struct request_logtime *) (request + HDR_LEN);
	struct display_params params;
	bool error;

	init_request_hdr(hdr, sizeof(request), MODE_LOGTIME, OP_DISPLAY);
	payload->l3_proto = (__u8) l3_proto;
	payload->l4_proto = (__u8) l4_proto;
	payload->display.iterate = false;

	params.row_count = 0;
	params.req_payload = payload;

	do {
		error = netlink_request(request, hdr->length, logtime_display_response, &params);
		if (error)
			break;
	} while (params.req_payload->display.iterate);

	if (!error) {
		if (params.row_count > 0)
			printf("  (Fetched %u entries.)\n", params.row_count);
		else
			printf("  (empty)\n");
	}

	return error;
}

int logtime_display()
{
	int tcp_ip6_error = 0;
	int udp_ip6_error = 0;
	int icmp_ip6_error = 0;
	int tcp_ip4_error = 0;
	int udp_ip4_error = 0;
	int icmp_ip4_error = 0;

	printf("L3 protocol,L4 Protocol,seconds,nanoseconds\n");
	tcp_ip6_error = display_single_db(L3PROTO_IPV6, L4PROTO_TCP);
	udp_ip6_error = display_single_db(L3PROTO_IPV6, L4PROTO_UDP);
	icmp_ip6_error = display_single_db(L3PROTO_IPV6, L4PROTO_ICMP);
	tcp_ip4_error = display_single_db(L3PROTO_IPV4, L4PROTO_TCP);
	udp_ip4_error = display_single_db(L3PROTO_IPV4, L4PROTO_UDP);
	icmp_ip4_error = display_single_db(L3PROTO_IPV4, L4PROTO_ICMP);

	return (tcp_ip6_error || udp_ip6_error || icmp_ip6_error || tcp_ip4_error || udp_ip4_error
			|| icmp_ip4_error ) ? -EINVAL : 0;
}

#endif /* BENCHMARK */
