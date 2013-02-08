#include "nat64/mode.h"

#include <time.h>

#include "nat64/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

static int session_display_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr;
	struct session_entry_us *entries;
	__u16 entry_count;
	__u16 i;
	char *str4;
	char str6[INET6_ADDRSTRLEN];

	hdr = nlmsg_data(nlmsg_hdr(msg));
	if (hdr->result_code != RESPONSE_SUCCESS) {
		print_code_msg(hdr, "Session table", NULL);
		return hdr->result_code;
	}

	entries = (struct session_entry_us *) (hdr + 1);
	entry_count = (hdr->length - sizeof(*hdr)) / sizeof(*entries);
	if (entry_count == 0) {
		printf("  (empty)\n\n");
		return 0;
	}

	printf("---------------------------------\n");

	for (i = 0; i < entry_count; i++) {
		struct session_entry_us *entry = &entries[i];

		if (entry->is_static)
			printf("STATIC\n");
		else
			printf("DYNAMIC (expires in %u milliseconds).\n", entry->dying_time);

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
	printf("\n");

	return 0;
}

static error_t exec_request(bool use_tcp, bool use_udp, bool use_icmp, struct request_hdr *hdr,
		struct request_session *payload, int (*callback)(struct nl_msg *msg, void *arg))
{
	error_t result = 0;

	if (use_tcp) {
		printf("TCP:\n");
		payload->l4_proto = IPPROTO_TCP;
		result |= netlink_request(hdr, hdr->length, callback);
	}
	if (use_udp) {
		printf("UDP:\n");
		payload->l4_proto = IPPROTO_UDP;
		result |= netlink_request(hdr, hdr->length, callback);
	}
	if (use_icmp) {
		printf("ICMP:\n");
		payload->l4_proto = IPPROTO_ICMP;
		result |= netlink_request(hdr, hdr->length, callback);
	}

	return result;
}

error_t session_display(bool use_tcp, bool use_udp, bool use_icmp)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_DISPLAY;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, session_display_response);
}

static int session_add_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "Session table", "The session entry was added successfully.");
	return 0;
}

error_t session_add(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6,
		struct ipv4_pair *pair4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_ADD;
	payload->add.pair6 = *pair6;
	payload->add.pair4 = *pair4;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, session_add_response);
}

static int session_remove_response(struct nl_msg *msg, void *arg)
{
	struct response_hdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	print_code_msg(hdr, "Session table", "The session entry was removed successfully.");
	return 0;
}

error_t session_remove_ipv4(bool use_tcp, bool use_udp, bool use_icmp, struct ipv4_pair *pair4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_REMOVE;
	payload->remove.l3_proto = 4;
	payload->remove.pair4 = *pair4;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, session_remove_response);
}

error_t session_remove_ipv6(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_REMOVE;
	payload->remove.l3_proto = 6;
	payload->remove.pair6 = *pair6;

	return exec_request(use_tcp, use_udp, use_icmp, hdr, payload, session_remove_response);
}
