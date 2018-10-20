#include "usr/common/argp/stats.h"

#include "usr/common/netlink.h"
#include "usr/common/userspace-types.h"
#include "usr/common/wargp.h"
#include "usr/common/nl/stats.h"

struct display_args {
	struct wargp_bool all;
	struct wargp_bool explain;
	struct wargp_bool no_headers;
	struct wargp_bool csv;
};

static struct wargp_option display_opts[] = {
	{
		.name = "all",
		.key = 'a',
		.doc = "Do not filter out zero stats",
		.offset = offsetof(struct display_args, all),
		.type = &wt_bool,
	}, {
		.name = "explain",
		.key = 'e',
		.doc = "Print a description of what each stat means",
		.offset = offsetof(struct display_args, explain),
		.type = &wt_bool,
	},
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

static int handle_jstat(struct jstat const *stat, void *args)
{
	struct display_args *dargs = args;

	if (!dargs->all.value && stat->value == 0)
		return 0;

	if (dargs->csv.value) {
		printf("%s,%llu", stat->meta.name, stat->value);
		if (dargs->explain.value)
			printf(",\"%s\"", stat->meta.doc);
	} else {
		printf("%s: %llu ", stat->meta.name, stat->value);
		if (dargs->explain.value)
			printf("(%s)", stat->meta.doc);
	}
	printf("\n");

	return 0;
}

int handle_stats_display(char *iname, int argc, char **argv, void *arg)
{
	struct display_args dargs = { 0 };
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	error = netlink_setup();
	if (error)
		return error;

	if (show_csv_header(dargs.no_headers.value, dargs.csv.value)) {
		printf("Stat,Value");
		if (dargs.explain.value)
			printf(",Explanation");
		printf("\n");
	}

	error = stats_foreach(iname, handle_jstat, &dargs);

	netlink_teardown();
	return error;
}

void print_stats_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}
