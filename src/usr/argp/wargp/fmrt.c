#include "usr/argp/wargp/fmrt.h"

#include "usr/argp/log.h"
#include "usr/argp/requirements.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/nl/core.h"
#include "usr/nl/fmrt.h"
#include "usr/util/str_utils.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
};

static struct wargp_option display_opts[] = {
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

static void print_separator(void)
{
	print_table_separator(0, 43, 18, 14, 2, 0);
}

static struct jool_result print_entry(struct mapping_rule const *entry, void *args)
{
	struct display_args *dargs = args;
	char ipv6_str[INET6_ADDRSTRLEN];
	char *ipv4_str;

	inet_ntop(AF_INET6, &entry->prefix6.addr, ipv6_str, sizeof(ipv6_str));
	ipv4_str = inet_ntoa(entry->prefix4.addr);

	if (dargs->csv.value) {
		printf("%s/%u,%s/%u,%u,%u\n",
				ipv6_str, entry->prefix6.len,
				ipv4_str, entry->prefix4.len,
				entry->o, entry->a);
	} else {
		printf("| %39s/%-3u | %15s/%-2u | %-14u | %2u |\n",
				ipv6_str, entry->prefix6.len,
				ipv4_str, entry->prefix4.len,
				entry->o, entry->a);
	}

	return result_success();
}

int handle_fmrt_display(char *iname, int argc, char **argv, void const *arg)
{
	struct display_args dargs = { 0 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(display_opts, argc, argv, &dargs);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	if (!dargs.no_headers.value) {
		static char const *const th1 = "IPv6 Prefix";
		static char const *const th2 = "IPv4 Prefix";
		static char const *const th3 = "EA-bits Length";
		static char const *const th4 = "a";
		if (dargs.csv.value)
			printf("%s,%s,%s,%s\n", th1, th2, th3, th4);
		else {
			print_separator();
			printf("| %43s | %18s | %s | %2s |\n", th1, th2, th3, th4);
			print_separator();
		}
	}

	result = joolnl_fmrt_foreach(&sk, iname, print_entry, &dargs);

	joolnl_teardown(&sk);

	if (result.error)
		return pr_result(&result);

	if (!dargs.csv.value)
		print_separator();
	return 0;
}

void autocomplete_fmrt_display(void const *args)
{
	print_wargp_opts(display_opts);
}

static struct wargp_option add_opts[] = {
	{
		.name = "Forwarding Mapping Rule",
		.key = ARGP_KEY_ARG,
		.doc = "The Basic Mapping Rule (BMR) of a MAP domain.",
		.offset = 0,
		.type = &wt_mapping_rule,
	},
	{ 0 },
};

typedef struct jool_result (*update_cb)(struct joolnl_socket *, char const *,
		struct mapping_rule const *);

int __handle_fmrt_update(char *iname, int argc, char **argv, void const *arg,
		update_cb cb)
{
	struct wargp_mapping_rule aargs = { .rule.a = 6 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(add_opts, argc, argv, &aargs);
	if (result.error)
		return result.error;

	if (aargs.fields < 3) {
		pr_err("Not enough arguments. Expected: %s",
				wt_mapping_rule.arg);
		pr_err("Arguments parsed: %u", aargs.fields);
		return -EINVAL;
	}

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = cb(&sk, iname, &aargs.rule);

	joolnl_teardown(&sk);
	return pr_result(&result);
}

int handle_fmrt_add(char *iname, int argc, char **argv, void const *arg)
{
	return __handle_fmrt_update(iname, argc, argv, arg, joolnl_fmrt_add);
}

void autocomplete_fmrt_add(void const *args)
{
	print_wargp_opts(add_opts);
}

int handle_fmrt_rm(char *iname, int argc, char **argv, void const *arg)
{
	return __handle_fmrt_update(iname, argc, argv, arg, joolnl_fmrt_rm);
}

void autocomplete_fmrt_rm(void const *args)
{
	print_wargp_opts(add_opts);
}

int handle_fmrt_flush(char *iname, int argc, char **argv, void const *arg)
{
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(add_opts, argc, argv, NULL);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joolnl_fmrt_flush(&sk, iname);

	joolnl_teardown(&sk);
	return pr_result(&result);
}

void autocomplete_fmrt_flush(void const *args)
{
	/* Nothing needed here. */
}
