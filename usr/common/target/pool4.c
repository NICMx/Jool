#include "nat64/usr/pool4.h"
#include "nat64/common/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct display_args {
	unsigned int row_count;
	union request_pool4 *request;
	bool csv;
};

static int pool4_display_response(struct nl_msg *response, void *arg)
{
	struct nlmsghdr *hdr;
	struct pool4_sample *samples;
	unsigned int sample_count, i;
	struct display_args *args = arg;

	hdr = nlmsg_hdr(response);
	samples = nlmsg_data(hdr);
	sample_count = nlmsg_datalen(hdr) / sizeof(*samples);

	if (args->row_count == 0 && args->csv)
		printf("Mark,Protocol,Address,Min port,Max port\n");

	for (i = 0; i < sample_count; i++) {
		if (args->csv)
			printf("%u,%s,%s,%u,%u\n", samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].addr),
					samples[i].range.min,
					samples[i].range.max);
		else
			printf("%u\t%s\t%s\t%u-%u\n", samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].addr),
					samples[i].range.min,
					samples[i].range.max);
	}

	args->row_count += sample_count;
	args->request->display.offset_set = hdr->nlmsg_flags & NLM_F_MULTI;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

	return 0;
}

int pool4_display(bool csv)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_DISPLAY);
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.csv = csv;

	do {
		error = netlink_request(&request, hdr->length, pool4_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	if (!csv) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)", args.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static int pool4_count_response(struct nl_msg *msg, void *arg)
{
	struct response_pool4_count *response = nlmsg_data(nlmsg_hdr(msg));

	printf("tables: %u\n", response->tables);
	printf("samples: %llu\n", response->samples);
	printf("transport addresses: %llu\n", response->taddrs);

	return 0;
}

int pool4_count(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_POOL4, OP_COUNT);
	return netlink_request(&request, request.length, pool4_count_response, NULL);
}

static int __add(__u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	if (addrs->len < 24 && !force) {
		printf("Warning: You're adding lots of addresses, which "
				"might defeat the whole point of NAT64 over "
				"SIIT.\n");
		printf("Also, and more or less as a consequence, addresses are "
				"stored in a linked list. Having too many "
				"addresses in pool4 sharing a mark is slow.\n");
		printf("Consider using SIIT instead.\n");
		printf("Will cancel the operation. Use --force to override "
				"this.\n");
		return -E2BIG;
	}

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_ADD);
	payload->add.mark = mark;
	payload->add.proto = proto;
	payload->add.addrs = *addrs;
	payload->add.ports = *ports;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_add(__u32 mark, bool tcp, bool udp, bool icmp,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool force)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (tcp)
		tcp_error = __add(mark, L4PROTO_TCP, addrs, ports, force);
	if (udp)
		udp_error = __add(mark, L4PROTO_UDP, addrs, ports, force);
	if (icmp)
		icmp_error = __add(mark, L4PROTO_ICMP, addrs, ports, force);

	return (tcp_error | udp_error | icmp_error) ? -EINVAL : 0;
}

static int __rm(__u32 mark, enum l4_protocol proto,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_REMOVE);
	payload->rm.mark = mark;
	payload->rm.proto = proto;
	payload->rm.addrs = *addrs;
	payload->rm.ports = *ports;
	payload->rm.quick = quick;

	return netlink_request(request, hdr->length, NULL, NULL);
}

int pool4_rm(__u32 mark, bool tcp, bool udp, bool icmp,
		struct ipv4_prefix *addrs, struct port_range *ports,
		bool quick)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (tcp)
		tcp_error = __rm(mark, L4PROTO_TCP, addrs, ports, quick);
	if (udp)
		udp_error = __rm(mark, L4PROTO_UDP, addrs, ports, quick);
	if (icmp)
		icmp_error = __rm(mark, L4PROTO_ICMP, addrs, ports, quick);

	return (tcp_error | udp_error | icmp_error) ? -EINVAL : 0;
}

int pool4_flush(bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);

	init_request_hdr(hdr, sizeof(request), MODE_POOL4, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, hdr->length, NULL, NULL);
}
