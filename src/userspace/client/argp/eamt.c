#include "eamt.h"

#include "requirements.h"
#include "userspace-types.h"
#include "usr-str-utils.h"
#include "wargp.h"
#include "netlink/eamt.h"

#define ARGP_FORCE 'f'

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
	unsigned int row_count;
};

static struct wargp_option display_opts[] = {
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

static int print_entry(struct eamt_entry *entry, void *args)
{
	struct display_args *eargs = args;
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->prefix6.addr, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->prefix4.addr);

	printf("%s/%u", ipv6_str, entry->prefix6.len);
	printf("%s", eargs->csv.value ? "," : " - ");
	printf("%s/%u", ipv4_str, entry->prefix4.len);
	printf("\n");

	eargs->row_count++;
	return 0;
}

int handle_eamt_display(int argc, char **argv)
{
	struct display_args eargs = { 0 };
	int error;

	error = wargp_parse(display_opts, argc, argv, &eargs);
	if (error)
		return error;

	if (show_csv_header(eargs.no_headers.value, eargs.csv.value))
		printf("IPv6 Prefix,IPv4 Prefix\n");

	error = eamt_foreach(print_entry, &eargs);
	if (error)
		return error;

	if (show_footer(eargs.no_headers.value, eargs.csv.value)) {
		if (eargs.row_count > 0)
			log_info("  (Fetched %u entries.)", eargs.row_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

void print_eamt_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}

struct wargp_eamt_entry {
	bool prefix6_set;
	bool prefix4_set;
	struct eamt_entry value;
};

struct add_args {
	struct wargp_eamt_entry entry;
	bool force;
};

static int parse_eamt_column(void *void_field, int key, char *str)
{
	struct wargp_eamt_entry *field = void_field;

	if (strchr(str, ':')) {
		field->prefix6_set = true;
		return str_to_prefix6(str, &field->value.prefix6);
	}
	if (strchr(str, '.')) {
		field->prefix4_set = true;
		return str_to_prefix4(str, &field->value.prefix4);
	}

	return ARGP_ERR_UNKNOWN;
}

struct wargp_type wt_prefixes = {
	.doc = "<IPv6 prefix> <IPv4 prefix>",
	.parse = parse_eamt_column,
};

static struct wargp_option add_opts[] = {
	{
		.name = "force",
		.key = ARGP_FORCE,
		.doc = "Ignore warnings.",
		.offset = offsetof(struct add_args, force),
		.type = &wt_bool,
	}, {
		.name = "Prefixes",
		.key = ARGP_KEY_ARG,
		.doc = "Prefixes (or addresses) that will shape the new EAMT entry",
		.offset = offsetof(struct add_args, entry),
		.type = &wt_prefixes,
	},
	{ 0 },
};

int handle_eamt_add(int argc, char **argv)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (!aargs.entry.prefix6_set || !aargs.entry.prefix4_set) {
		struct requirement reqs[] = {
				{ aargs.entry.prefix6_set, "an IPv6 prefix" },
				{ aargs.entry.prefix4_set, "an IPv4 prefix" },
				{ 0 },
		};
		return requirement_print(reqs);
	}

	return eamt_add(&aargs.entry.value.prefix6, &aargs.entry.value.prefix4,
			aargs.force);
}

void print_eamt_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
}

struct rm_args {
	struct wargp_eamt_entry entry;
};

static struct wargp_option remove_opts[] = {
	{
		.name = "Prefixes",
		.key = ARGP_KEY_ARG,
		.doc = "Prefixes (or addresses) that shape the EAMT entry you want to remove",
		.offset = offsetof(struct rm_args, entry),
		.type = &wt_prefixes,
	},
	{ 0 },
};

int handle_eamt_remove(int argc, char **argv)
{
	struct rm_args rargs = { 0 };
	int error;

	error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (error)
		return error;

	if (!rargs.entry.prefix6_set && !rargs.entry.prefix4_set) {
		struct requirement reqs[] = {
				{ false, "a prefix" },
				{ 0 },
		};
		return requirement_print(reqs);
	}

	return eamt_rm(&rargs.entry.value.prefix6, &rargs.entry.value.prefix4);
}

void print_eamt_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
}

int handle_eamt_flush(int argc, char **argv)
{
	int error;

	/*
	 * We still call wargp_parse despite not having any arguments because
	 * there's still --help and --usage that a clueless user might expect.
	 */
	error = wargp_parse(NULL, argc, argv, NULL);
	if (error)
		return error;

	return eamt_flush();
}

void print_eamt_flush_opts(char *prefix)
{
	/* Nothing needed here. */
}
