#include "nat64/usr/bib.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_bib)

static int bib_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr;
	struct bib_entry_us *entries;
	__u16 entry_count;
	__u16 i;
	char addr_str[INET6_ADDRSTRLEN];

	hdr = nlmsg_data(nlmsg_hdr(msg));
	entries = (struct bib_entry_us *) (hdr + 1);
	entry_count = (hdr->length - sizeof(*hdr)) / sizeof(*entries);

	if (hdr->result_code != ERR_SUCCESS) {
		print_code_msg(hdr->result_code, NULL);
		return EINVAL;
	}

	if (entry_count == 0)
		printf("  (empty)\n");
	for (i = 0; i < entry_count; i++) {
		inet_ntop(AF_INET6, &entries[i].ipv6.address, addr_str, INET6_ADDRSTRLEN);
		printf("%s#%u - %s#%u\n",
				inet_ntoa(entries[i].ipv4.address),
				entries[i].ipv4.l4_id,
				addr_str,
				entries[i].ipv6.l4_id);
	}
	printf("\n");

	return 0;
}

int bib_display(bool use_tcp, bool use_udp, bool use_icmp)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_bib *payload = (union request_bib *) (request + HDR_LEN);
	int tcp_error, udp_error, icmp_error;

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_DISPLAY;

	if (use_tcp) {
		printf("TCP:\n");
		payload->display.l4_proto = IPPROTO_TCP;
		tcp_error = netlink_request(request, hdr->length, bib_display_response);
	}
	if (use_udp) {
		printf("UDP:\n");
		payload->display.l4_proto = IPPROTO_UDP;
		udp_error = netlink_request(request, hdr->length, bib_display_response);
	}
	if (use_icmp) {
		printf("ICMP:\n");
		payload->display.l4_proto = IPPROTO_ICMP;
		icmp_error = netlink_request(request, hdr->length, bib_display_response);
	}

	return (tcp_error || udp_error || icmp_error) ? EINVAL : 0;
}
