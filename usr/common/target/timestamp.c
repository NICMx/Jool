#include <errno.h>

#include "nat64/usr/timestamp.h"
#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

static void print_entry(struct timestamps_entry_usr *entries, char *prefix)
{
	if (entries->success_count == 0
			&& entries->success_min == 0
			&& entries->success_avg == 0
			&& entries->success_max == 0
			&& entries->failure_count == 0
			&& entries->failure_min == 0
			&& entries->failure_avg == 0
			&& entries->failure_max == 0)
		return;

	printf("%s\n", prefix);
	printf("Success count: %u\n", entries->success_count);
	printf("Success minimum: %u\n", entries->success_min);
	printf("Success average: %u\n", entries->success_avg);
	printf("Success maximum: %u\n", entries->success_max);
	printf("Failure count: %u\n", entries->failure_count);
	printf("Failure minimum: %u\n", entries->failure_min);
	printf("Failure average: %u\n", entries->failure_avg);
	printf("Failure maximum: %u\n", entries->failure_max);
	printf("\n");
}

static int handle_display(struct jool_response *response, void *arg)
{
	struct timestamps_entry_usr *entries = response->payload;
	unsigned int i = 0;

	if (response->payload_len != TST_LENGTH * sizeof(*entries)) {
		printf("Error: The kernel module responded %zu bytes, %zu expected.\n",
				response->payload_len,
				TST_LENGTH * sizeof(*entries));
		return -EINVAL;
	}

	print_entry(&entries[i++], "6->4: Full translations");
	print_entry(&entries[i++], "6->4: Incoming packet validations");
	print_entry(&entries[i++], "4->6: Full translations");
	print_entry(&entries[i++], "4->6: Incoming packet validations");

	print_entry(&entries[i++], "'Determine Incoming Tuple' step");
	print_entry(&entries[i++], "'Filtering and Updating' step");
	print_entry(&entries[i++], "'Compute Outgoing Tuple' step");
	print_entry(&entries[i++], "'Translating the Packet' step");
	print_entry(&entries[i++], "'Handling Hairpinning' step");
	print_entry(&entries[i++], "'Send packet' step");

	print_entry(&entries[i++], "6->4 Filtering and Updating validations");
	print_entry(&entries[i++], "4->6 Filtering and Updating validations");
	print_entry(&entries[i++], "Mask Domain searches");

	print_entry(&entries[i++], "6->4 UDP/ICMP session lookup - Found");
	print_entry(&entries[i++], "6->4 UDP/ICMP session lookup - Created");
	print_entry(&entries[i++], "4->6 UDP/ICMP session lookup - Found");
	print_entry(&entries[i++], "6->4 TCP session lookup - Found");
	print_entry(&entries[i++], "6->4 TCP session lookup - Created");
	print_entry(&entries[i++], "4->6 TCP session lookup - Found");
	print_entry(&entries[i++], "Generic session lookup - Found");
	print_entry(&entries[i++], "Generic session lookup - Created");
	print_entry(&entries[i++], "Session expiration timer");
	print_entry(&entries[i++], "Session probing");
	print_entry(&entries[i++], "Session mask allocation");

	print_entry(&entries[i++], "ICMPv6 error");
	print_entry(&entries[i++], "ICMPv4 error");

	return 0;
}

int timestamp_display(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, MODE_TIMESTAMPS, OP_DISPLAY);
	return netlink_request(&hdr, sizeof(hdr), handle_display, NULL);
}
