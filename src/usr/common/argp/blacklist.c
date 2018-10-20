#include "usr/common/argp/blacklist.h"

#include "usr/common/netlink.h"
#include "usr/common/requirements.h"
#include "usr/common/userspace-types.h"
#include "usr/common/str_utils.h"
#include "usr/common/wargp.h"
#include "usr/common/nl/blacklist.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
};

static struct wargp_option display_opts[] = {
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

static int print_entry(struct ipv4_prefix *prefix, void *args)
{
	char *prefix_str;

	prefix_str = inet_ntoa(prefix->addr);
	printf("%s/%u", prefix_str, prefix->len);
	printf("\n");

	return 0;
}

int handle_blacklist_display(char *iname, int argc, char **argv, void *arg)
{
	struct display_args dargs = { 0 };
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	error = netlink_setup();
	if (error)
		return error;

	if (show_csv_header(dargs.no_headers.value, dargs.csv.value))
		printf("IPv4 Prefix\n");

	error = blacklist_foreach(iname, print_entry, &dargs);

	netlink_teardown();

	return error;
}

void print_blacklist_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}

struct add_args {
	bool force;
	struct wargp_prefix4 prefix;
};

static struct wargp_option add_opts[] = {
	WARGP_FORCE(struct add_args, force),
	{
		.name = "Prefixes",
		.key = ARGP_KEY_ARG,
		.doc = "Prefixes (or addresses) that will shape the new EAMT entry",
		.offset = offsetof(struct add_args, prefix),
		.type = &wt_prefix4,
	},
	{ 0 },
};

int handle_blacklist_add(char *iname, int argc, char **argv, void *arg)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (!aargs.prefix.set) {
		struct requirement reqs[] = {
				{ false, "an IPv4 prefix" },
				{ 0 },
		};
		return requirement_print(reqs);
	}

	error = netlink_setup();
	if (error)
		return error;

	error = blacklist_add(iname, &aargs.prefix.prefix, aargs.force);

	netlink_teardown();
	return error;
}

void print_blacklist_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
}

struct rm_args {
	struct wargp_prefix4 prefix;
};

static struct wargp_option remove_opts[] = {
	{
		.name = "Prefixes",
		.key = ARGP_KEY_ARG,
		.doc = "Prefixes (or addresses) that shape the EAMT entry you want to remove",
		.offset = offsetof(struct rm_args, prefix),
		.type = &wt_prefix4,
	},
	{ 0 },
};

int handle_blacklist_remove(char *iname, int argc, char **argv, void *arg)
{
	struct rm_args rargs = { 0 };
	int error;

	error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (error)
		return error;

	if (!rargs.prefix.set) {
		struct requirement reqs[] = {
				{ false, "an IPv4 prefix" },
				{ 0 },
		};
		return requirement_print(reqs);
	}

	error = netlink_setup();
	if (error)
		return error;

	error = blacklist_rm(iname, &rargs.prefix.prefix);

	netlink_teardown();
	return error;
}

void print_blacklist_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
}

int handle_blacklist_flush(char *iname, int argc, char **argv, void *arg)
{
	int error;

	error = wargp_parse(NULL, argc, argv, NULL);
	if (error)
		return error;

	error = netlink_setup();
	if (error)
		return error;

	error = blacklist_flush(iname);

	netlink_teardown();
	return error;
}

void print_blacklist_flush_opts(char *prefix)
{
	/* Nothing needed here. */
}
