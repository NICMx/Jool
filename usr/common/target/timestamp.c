#include <errno.h>

#include "nat64/usr/timestamp.h"
#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

static void print_entry(struct timestamps_entry_usr *entries, char *prefix)
{
	if (entries->success_count == 0 && entries->failure_count == 0)
		return;

	printf("%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n", prefix,
			entries->success_count, entries->success_min,
			entries->success_avg, entries->success_max,
			entries->failure_count, entries->failure_min,
			entries->failure_avg, entries->failure_max);

	/*
	printf("Success count: %u\n", );
	printf("Success minimum: %u\n", );
	printf("Success average: %u\n", );
	printf("Success maximum: %u\n", );
	printf("Failure count: %u\n", );
	printf("Failure minimum: %u\n", );
	printf("Failure average: %u\n", );
	printf("Failure maximum: %u\n", );
	printf("\n");
	*/
}

static void print_batch(unsigned int index, struct timestamps_entry_usr *entry)
{
	printf("\tBatch %u\n", index);

	print_entry(entry++, "6->4: Full translations");
	print_entry(entry++, "6->4: Incoming packet validations");
	print_entry(entry++, "4->6: Full translations");
	print_entry(entry++, "4->6: Incoming packet validations");

	print_entry(entry++, "'Determine Incoming Tuple' step");
	print_entry(entry++, "'Filtering and Updating' step");
	print_entry(entry++, "'Compute Outgoing Tuple' step");
	print_entry(entry++, "'Translating the Packet' step");
	print_entry(entry++, "'Handling Hairpinning' step");
	print_entry(entry++, "'Send packet' step");

	print_entry(entry++, "6->4 Filtering and Updating validations");
	print_entry(entry++, "4->6 Filtering and Updating validations");
	print_entry(entry++, "Mask Domain searches");

	print_entry(entry++, "6->4 UDP/ICMP session lookup - Found");
	print_entry(entry++, "6->4 UDP/ICMP session lookup - Created");
	print_entry(entry++, "4->6 UDP/ICMP session lookup - Found");
	print_entry(entry++, "6->4 TCP session lookup - Found");
	print_entry(entry++, "6->4 TCP session lookup - Created");
	print_entry(entry++, "4->6 TCP session lookup - Found");
	print_entry(entry++, "Generic session lookup - Found");
	print_entry(entry++, "Generic session lookup - Created");
	print_entry(entry++, "Session expiration timer");
	print_entry(entry++, "Session probing");
	print_entry(entry++, "Session mask allocation");

	print_entry(entry++, "ICMPv6 error");
	print_entry(entry++, "ICMPv4 error");

	printf("\n");
}

static int handle_display(struct jool_response *response, void *arg)
{
	struct timestamps_entry_usr *entries = response->payload;
	unsigned int b, batch_count;
	size_t batch_size;

	batch_size = TST_LENGTH * sizeof(*entries);

	if (response->payload_len % batch_size != 0) {
		printf("Error: The kernel module responded %zu bytes, multiple of %zu expected.\n",
				response->payload_len,
				TST_LENGTH * sizeof(*entries));
		return -EINVAL;
	}

	batch_count = response->payload_len / batch_size;
	for (b = 0; b < batch_count; b++)
		print_batch(b + 1, &entries[TST_LENGTH * b]);

	return 0;
}

int timestamp_display(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_TIMESTAMPS, OP_DISPLAY);
	return netlink_request(&hdr, sizeof(hdr), handle_display, NULL);
}
