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
	if (entry->fw == FW_NETFILTER)
		printf("netfilter,");
	else if (entry->fw == FW_IPTABLES)
		printf("iptables,");
	else
		printf("unknown,");
	printf("%s\n", entry->iname);
}

static void print_table_divisor(void)
{
	printf("+--------------------+-----------+-----------------+\n");
}

static void print_entry_normal(struct instance_entry_usr *entry)
{
	/*
	 * 18 is "0x" plus 16 hexadecimal digits.
	 * Why is it necessary? Because the table headers and stuff assume 18
	 * characters and I'm assuming that 32-bit machines would print smaller
	 * pointers.
	 */
	printf("| %18p | ", entry->ns);
	if (entry->fw == FW_NETFILTER)
		printf("netfilter");
	else if (entry->fw == FW_IPTABLES)
		printf(" iptables");
	else
		printf("  unknown");
	printf(" | %15s |\n", entry->iname);
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

	if (flags & DF_SHOW_HEADERS) {
		if (flags & DF_CSV_FORMAT) {
			printf("Namespace,Framework,Name\n");
		} else {
			print_table_divisor();
			printf("|          Namespace | Framework |            Name |\n");
		}
	}

	if (!(flags & DF_CSV_FORMAT))
		print_table_divisor();

	do {
		error = netlink_request(NULL, request, sizeof(request),
				instance_display_response, &args);
		if (error)
			return error;
	} while (payload->display.offset_set);

	if (args.row_count > 0 && !(flags & DF_CSV_FORMAT))
		print_table_divisor();

	if (show_footer(flags)) {
		if (args.row_count > 0)
			log_info("  (Fetched %u entries.)", args.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

int instance_add(int fw, char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	int error;

	error = fw_validate(fw);
	if (error)
		return error;
	error = iname_validate(iname, true);
	if (error)
		return error;

	init_request_hdr(hdr, MODE_INSTANCE, OP_ADD);
	payload->add.fw = fw;
	strcpy(payload->add.iname, iname ?: INAME_DEFAULT);

	return netlink_request(NULL, request, sizeof(request), NULL, NULL);
}

int instance_rm(char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	int error;

	error = iname_validate(iname, true);
	if (error)
		return error;

	init_request_hdr(hdr, MODE_INSTANCE, OP_REMOVE);
	strcpy(payload->rm.iname, iname ?: INAME_DEFAULT);

	return netlink_request(NULL, request, sizeof(request), NULL, NULL);
}

int instance_flush(void)
{
	struct request_hdr request;
	init_request_hdr(&request, MODE_INSTANCE, OP_FLUSH);
	return netlink_request(NULL, &request, sizeof(request), NULL, NULL);
}
