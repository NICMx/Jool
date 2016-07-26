#include "nat64/usr/pool4.h"

#include <errno.h>
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct display_args {
	unsigned int row_count;
	union request_pool4 *request;
	bool csv;
};

static int pool4_display_response(struct jool_response *response, void *arg)
{
	struct pool4_sample *samples = response->payload;
	unsigned int sample_count, i;
	struct display_args *args = arg;

	sample_count = response->payload_len / sizeof(*samples);

	if (args->row_count == 0 && args->csv)
		printf("Mark,Protocol,Address,Min port,Max port\n");

	for (i = 0; i < sample_count; i++) {
		if (args->csv)
			printf("%u,%s,%s,%u,%u\n", samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].range.addr),
					samples[i].range.ports.min,
					samples[i].range.ports.max);
		else
			printf("%u\t%s\t%s\t%u-%u\n", samples[i].mark,
					l4proto_to_string(samples[i].proto),
					inet_ntoa(samples[i].range.addr),
					samples[i].range.ports.min,
					samples[i].range.ports.max);
	}

	args->row_count += sample_count;
	args->request->display.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

	return 0;
}

int pool4_display_proto(bool csv, l4_protocol proto, unsigned int *count)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	union request_pool4 *payload = (union request_pool4 *) (request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, MODE_POOL4, OP_DISPLAY);
	payload->display.proto = proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.row_count = 0;
	args.request = payload;
	args.csv = csv;

	do {
		error = netlink_request(&request, sizeof(request),
				pool4_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	*count += args.row_count;
	return 0;
}

int pool4_display(bool csv)
{
	int error;
	unsigned int count = 0;

	error = pool4_display_proto(csv, L4PROTO_TCP, &count);
	if (error)
		return error;
	error = pool4_display_proto(csv, L4PROTO_UDP, &count);
	if (error)
		return error;
	error = pool4_display_proto(csv, L4PROTO_ICMP, &count);
	if (error)
		return error;

	if (!csv) {
		if (count > 0)
			log_info("  (Fetched %u samples.)", count);
		else
			log_info("  (empty)");
	}

	return 0;
}

int pool4_count(void)
{
	log_err("Sorry; --pool4 --count is not implemented anymore.");
	log_err("See https://github.com/NICMx/pool4-usage-analyzer");
	return -EINVAL;
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

	init_request_hdr(hdr, MODE_POOL4, OP_ADD);
	payload->add.entry.mark = mark;
	payload->add.entry.proto = proto;
	payload->add.entry.range.prefix = *addrs;
	payload->add.entry.range.ports = *ports;

	return netlink_request(request, sizeof(request), NULL, NULL);
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

	init_request_hdr(hdr, MODE_POOL4, OP_REMOVE);
	payload->rm.entry.mark = mark;
	payload->rm.entry.proto = proto;
	payload->rm.entry.range.prefix = *addrs;
	payload->rm.entry.range.ports = *ports;
	payload->rm.quick = quick;

	return netlink_request(request, sizeof(request), NULL, NULL);
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

	init_request_hdr(hdr, MODE_POOL4, OP_FLUSH);
	payload->flush.quick = quick;

	return netlink_request(&request, sizeof(request), NULL, NULL);
}
