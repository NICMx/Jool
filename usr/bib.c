#include "nat64/usr/bib.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_bib)


static int bib_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct bib_entry_us *entries;
	__u16 entry_count, i;
	char addr_str[INET6_ADDRSTRLEN];

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		inet_ntop(AF_INET6, &entries[i].ipv6.address, addr_str, INET6_ADDRSTRLEN);
		printf("%s#%u - %s#%u\n",
				inet_ntoa(entries[i].ipv4.address),
				entries[i].ipv4.l4_id,
				addr_str,
				entries[i].ipv6.l4_id);
	}

	*((int *) arg) += entry_count;
	return 0;
}

static bool display_single_table(char *table_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_bib *payload = (union request_bib *) (request + HDR_LEN);
	int row_count = 0;
	bool error;

	printf("%s:\n", table_name);

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_DISPLAY;
	payload->display.l4_proto = l4_proto;

	error = netlink_request(request, hdr->length, bib_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			printf("  (Fetched %u entries.)\n", row_count);
		else
			printf("  (empty)\n");
	}

	return error;
}

int bib_display(bool use_tcp, bool use_udp, bool use_icmp)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_table("TCP", IPPROTO_TCP);
	if (use_udp)
		udp_error = display_single_table("UDP", IPPROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_table("ICMP", IPPROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? EINVAL : 0;
}
