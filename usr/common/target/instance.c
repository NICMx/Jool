#include "nat64/usr/instance.h"

#include <errno.h>
#include "nat64/common/config.h"
#include "nat64/usr/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_instance)

struct display_args {
	display_flags flags;
	unsigned int row_count;
	union request_instance *request;
};

static void print_entry_csv(struct instance_entry_usr *entry)
{
	printf("%p,", entry->ns);
	if (entry->it == IT_NETFILTER)
		printf("netfilter,");
	else if (entry->it == IT_IPTABLES)
		printf("iptables,");
	else
		printf("unknown,");
	printf("%s\n", entry->name);
}

static void print_entry_normal(struct instance_entry_usr *entry)
{
	printf("| %p |", entry->ns);
	if (entry->it == IT_NETFILTER)
		printf("netfilter");
	else if (entry->it == IT_IPTABLES)
		printf(" iptables");
	else
		printf("  unknown");
	printf("| %15s |\n", entry->name);
}

static int instance_display_response(struct jool_response *response, void *arg)
{
	struct instance_entry_usr *entries = response->payload;
	struct display_args *args = arg;
	__u16 entry_count, i;

	entry_count = response->payload_len / sizeof(*entries);

	if (args->flags & DF_CSV_FORMAT) {
		for (i = 0; i < entry_count; i++)
			print_entry_csv(&entries[i]);
	} else {
		for (i = 0; i < entry_count; i++)
			print_entry_normal(&entries[i]);
	}

	args->row_count += entry_count;
	args->request->display.offset_set = response->hdr->pending_data;
	if (entry_count > 0)
		args->request->display.offset = entries[entry_count - 1];
	return 0;
}

int instance_display(display_flags flags)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	struct display_args args;
	int error;

	init_request_hdr(hdr, MODE_INSTANCE, OP_DISPLAY);
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));
	args.flags = flags;
	args.row_count = 0;
	args.request = payload;

	if ((flags & DF_SHOW_HEADERS) && (flags & DF_CSV_FORMAT))
		printf("Namespace,Type,Name\n");

	do {
		error = netlink_request(NULL, request, sizeof(request),
				instance_display_response, &args);
		if (error)
			return error;
	} while (payload->display.offset_set);

	if (show_footer(flags)) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)", args.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static unsigned int count_bits(int type)
{
	unsigned int i = 0;
	unsigned int result = 0;

	for (; i < 8 * sizeof(int); i++) {
		if (type & 1)
			result++;
		type >>= 1;
	}

	return result;
}

int instance_add(int type, char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	int error;

	if (count_bits(type) != 1) {
		log_err("Only one instance type can be added at a time.");
		return -EINVAL;
	}
	error = iname_validate(iname);
	if (error)
		return error;

	init_request_hdr(hdr, MODE_INSTANCE, OP_ADD);
	payload->add.it = type;
	strcpy(payload->add.name, iname);

	return netlink_request(NULL, request, sizeof(request), NULL, NULL);
}

int instance_rm(int type, char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	int error;

	error = iname_validate(iname);
	if (error)
		return error;

	init_request_hdr(hdr, MODE_INSTANCE, OP_REMOVE);
	payload->rm.it = type;
	strcpy(payload->rm.name, iname);

	return netlink_request(NULL, request, sizeof(request), NULL, NULL);
}
