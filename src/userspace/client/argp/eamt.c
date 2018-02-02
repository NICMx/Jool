#include "eamt.h"

#include <argp.h>

#include "netlink.h"
#include "userspace-types.h"
#include "usr-str-utils.h"
#include "netlink/eamt.h"

#define ARGP_CSV 2000
#define ARGP_NO_HEADERS 2001
#define ARGP_FORCE 2002

struct eamt_argp_args {
	display_flags flags;
	bool force;

	bool prefix6_set;
	struct ipv6_prefix prefix6;
	bool prefix4_set;
	struct ipv4_prefix prefix4;

	unsigned int row_count;
};

static struct argp_option argp_display_opts[] = {
	{
		.name = "no-headers",
		.key = ARGP_NO_HEADERS,
		.doc = "Do not print table headers.",
	},
	{
		.name = "csv",
		.key = ARGP_CSV,
		.doc = "Print in CSV format.",
	},
	{ 0 },
};

static struct argp_option argp_add_opts[] = {
	{
		.name = "force",
		.key = ARGP_FORCE,
		.doc = "Ignore warnings.",
	},
	{ 0 },
};

static int parse_display_opts(int key, char *str, struct argp_state *state)
{
	struct eamt_argp_args *eargs = state->input;

	switch (key) {
	case ARGP_CSV:
		eargs->flags |= DF_CSV_FORMAT;
		return 0;
	case ARGP_NO_HEADERS:
		eargs->flags |= DF_NO_HEADERS;
		return 0;
	}

	return ARGP_ERR_UNKNOWN;
}

static int print_entry(struct eamt_entry *entry, void *args)
{
	struct eamt_argp_args *eargs = args;
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->prefix6.addr, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->prefix4.addr);

	printf("%s/%u", ipv6_str, entry->prefix6.len);
	printf("%s", (eargs->flags & DF_CSV_FORMAT) ? "," : " - ");
	printf("%s/%u", ipv4_str, entry->prefix4.len);
	printf("\n");

	eargs->row_count++;
	return 0;
}

int handle_eamt_display(int argc, char **argv)
{
	/* TODO review what these NULLs are for and possibly delete them. */
	static struct argp argp = {
			argp_display_opts,
			parse_display_opts,
			NULL,
			NULL
	};
	struct eamt_argp_args eargs;
	int error;

	memset(&eargs, 0, sizeof(eargs));
	error = argp_parse(&argp, argc, argv, 0, NULL, &eargs);
	if (error)
		return error;

	if (show_csv_header(eargs.flags))
		printf("IPv6 Prefix,IPv4 Prefix\n");

	error = eamt_foreach(print_entry, &eargs);
	if (error)
		return error;

	if (show_footer(eargs.flags)) {
		if (eargs.row_count > 0)
			log_info("  (Fetched %u entries.)", eargs.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static int parse_eamt_column(struct request_eamt_add *request, char *str)
{
	if (!str || strlen(str) == 0)
		return 0; /* TODO should be an error? */

	if (strchr(str, ':'))
		return str_to_prefix6(str, &request->prefix6);
	if (strchr(str, '.'))
		return str_to_prefix4(str, &request->prefix4);

	/* TODO error msg ?*/
	return -EINVAL;
}

static int parse_add_opts(int key, char *str, struct argp_state *state)
{
	struct request_eamt_add *request = state->input;

	switch (key) {
	case ARGP_FORCE:
		request->force = true;
		return 0;
	case ARGP_KEY_ARG:
		return parse_eamt_column(request, str);
	}

	return ARGP_ERR_UNKNOWN;
}

int handle_eamt_add(int argc, char **argv)
{
	struct eamt_argp_args eargs;
	static struct argp argp = { argp_add_opts, parse_add_opts, NULL, NULL };
	int error;

	memset(&eargs, 0, sizeof(eargs));
	error = argp_parse(&argp, argc, argv, 0, NULL, &eargs);
	if (error)
		return error;

	return eamt_add(eargs.prefix6_set ? &eargs.prefix6 : NULL,
			eargs.prefix4_set ? &eargs.prefix4 : NULL,
			eargs.force);
}

int handle_eamt_remove(int argc, char **argv)
{
	struct ipv6_prefix prefix6, *prefix6_ptr = NULL;
	struct ipv4_prefix prefix4, *prefix4_ptr = NULL;
	unsigned int i;
	int error;

	for (i = 0; i < argc; i++) {
		if (strchr(argv[i], ':')) {
			if (prefix6_ptr) {
				log_err("Expected only one v6 prefix (or address).");
				return -EINVAL;
			}

			error = str_to_prefix6(argv[i], &prefix6);
			if (error)
				return error;
			prefix6_ptr = &prefix6;
			continue;
		}

		if (strchr(argv[i], '.')) {
			if (prefix4_ptr) {
				log_err("Expected only one v4 prefix (or address).");
				return -EINVAL;
			}

			error = str_to_prefix4(argv[i], &prefix4);
			if (error)
				return error;
			prefix4_ptr = &prefix4;
			continue;
		}

		log_err("I don't know what '%s' is.", argv[i]);
		log_err("Expected IPv4/6 prefixes or addresses as arguments.");
		return -EINVAL;
	}

	return eamt_rm(prefix6_ptr, prefix4_ptr);
}

int handle_eamt_flush(int argc, char **argv)
{
	if (argc != 1) {
		log_err("flush does not expect any arguments.");
		return -EINVAL;
	}

	return eamt_flush();
}
