#include "nat64/usr/session.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>
#include <time.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)


static int session_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct session_entry_us *entries;
	__u16 entry_count, i;

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		struct session_entry_us *entry = &entries[i];
		char *str4;
		char str6[INET6_ADDRSTRLEN];

		printf("Expires in ");
		print_time(entry->dying_time);

		str4 = inet_ntoa(entry->ipv4.remote.address);
		printf("Remote: %s#%u\t", str4, entry->ipv4.remote.l4_id);
		inet_ntop(AF_INET6, &entry->ipv6.remote.address, str6, INET6_ADDRSTRLEN);
		printf("%s#%u\n", str6, entry->ipv6.remote.l4_id);

		str4 = inet_ntoa(entry->ipv4.local.address);
		printf("Local: %s#%u\t", str4, entry->ipv4.local.l4_id);
		inet_ntop(AF_INET6, &entry->ipv6.local.address, str6, INET6_ADDRSTRLEN);
		printf("%s#%u\n", str6, entry->ipv6.local.l4_id);

		printf("---------------------------------\n");
	}

	*((int *) arg) += entry_count;
	return 0;
}

static bool display_single_table(char *table_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);
	int row_count = 0;
	bool error;

	printf("%s:\n", table_name);
	printf("---------------------------------\n");

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_DISPLAY;
	payload->l4_proto = l4_proto;

	error = netlink_request(request, hdr->length, session_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			log_info("  (Fetched %u entries.)\n", row_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}

int session_display(bool use_tcp, bool use_udp, bool use_icmp)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_table("TCP", L4PROTO_TCP);
	if (use_udp)
		udp_error = display_single_table("UDP", L4PROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_table("ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}
