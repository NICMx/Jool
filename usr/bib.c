#include "nat64/usr/bib.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_bib)


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
		printf("[%s] %s#%u - %s#%u\n",
				entries[i].is_static ? "Static" : "Dynamic",
				inet_ntoa(entries[i].ipv4.address),
				entries[i].ipv4.l4_id,
				addr_str,
				entries[i].ipv6.l4_id);
	}

	*((int *) arg) += entry_count;
	return 0;
}

static bool display_single_table(char *table_name, l4_protocol l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);
	int row_count = 0;
	bool error;

	printf("%s:\n", table_name);

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_DISPLAY;
	payload->l4_proto = l4_proto;

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
		tcp_error = display_single_table("TCP", L4PROTO_TCP);
	if (use_udp)
		udp_error = display_single_table("UDP", L4PROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_table("ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int exec_request(bool use_tcp, bool use_udp, bool use_icmp, struct request_hdr *hdr,
		struct request_bib *payload, int (*callback)(struct nl_msg *msg, void *arg))
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp) {
		printf("TCP:\n");
		payload->l4_proto = L4PROTO_TCP;
		tcp_error = netlink_request(hdr, hdr->length, callback, NULL);
	}
	if (use_udp) {
		printf("UDP:\n");
		payload->l4_proto = L4PROTO_UDP;
		udp_error = netlink_request(hdr, hdr->length, callback, NULL);
	}
	if (use_icmp) {
		printf("ICMP:\n");
		payload->l4_proto = L4PROTO_ICMP;
		icmp_error = netlink_request(hdr, hdr->length, callback, NULL);
	}

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int bib_add_response(struct nl_msg *msg, void *arg)
{
	log_info("The BIB entry was added successfully.");
	return 0;
}

int bib_add(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_tuple_address *ipv6,
		struct ipv4_tuple_address *ipv4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_ADD;
	payload->add.ipv6 = *ipv6;
	payload->add.ipv4 = *ipv4;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, bib_add_response);
}

static int bib_remove_response(struct nl_msg *msg, void *arg)
{
	log_info("The BIB entry was removed successfully.");
	return 0;
}

int bib_remove_ipv6(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_tuple_address *ipv6)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_REMOVE;
	payload->remove.l3_proto = L3PROTO_IPV6;
	payload->remove.ipv6 = *ipv6;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, bib_remove_response);
}

int bib_remove_ipv4(bool use_tcp, bool use_udp, bool use_icmp, struct ipv4_tuple_address *ipv4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_bib *payload = (struct request_bib *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_BIB;
	hdr->operation = OP_REMOVE;
	payload->remove.l3_proto = L3PROTO_IPV4;
	payload->remove.ipv4 = *ipv4;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, bib_remove_response);
}
