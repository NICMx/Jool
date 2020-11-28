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
				entry->ea_bits_length,
				entry->a);
	} else {
		printf("| %39s/%-3u | %15s/%-2u | %-14u | %2u |\n",
				ipv6_str, entry->prefix6.len,
				ipv4_str, entry->prefix4.len,
				entry->ea_bits_length, entry->a);
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

struct wargp_mapping_rule {
	struct wargp_prefix6 prefix6;
	struct wargp_prefix4 prefix4;
	struct wargp_u8 ea_bits_length;
};

struct add_args {
	struct wargp_mapping_rule rule;
	struct wargp_u8 a;
};

static int parse_fmrt_column(void *void_field, int key, char *str)
{
	struct wargp_mapping_rule *field = void_field;
	struct jool_result result;

	if (strchr(str, ':')) {
		field->prefix6.set = true;
		result = str_to_prefix6(str, &field->prefix6.prefix);
		return pr_result(&result);
	}
	if (strchr(str, '.')) {
		field->prefix4.set = true;
		result = str_to_prefix4(str, &field->prefix4.prefix);
		return pr_result(&result);
	}
	result = str_to_u8(str, &field->ea_bits_length.value, 128);
	if (result.error)
		return pr_result(&result);

	field->ea_bits_length.set = true;
	return 0;
}

struct wargp_type wt_rule = {
	.argument = "<IPv6 prefix> <IPv4 prefix> <EA-bits Length>",
	.parse = parse_fmrt_column,
};

static struct wargp_option add_opts[] = {
	{
		.name = "Mapping Rule",
		.key = ARGP_KEY_ARG,
		.doc = "Prefixes and EA-bits Length that will shape the new FMR",
		.offset = offsetof(struct add_args, rule),
		.type = &wt_rule,
	}, {
		.name = "a",
		.key = 'a',
		.doc = "a", /* TODO (MAP-T) */
		.offset = offsetof(struct add_args, a),
		.type = &wt_u8,
	},
	{ 0 },
};

int handle_fmrt_add(char *iname, int argc, char **argv, void const *arg)
{
	struct add_args aargs = { 0 };
	struct mapping_rule fmr;
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(add_opts, argc, argv, &aargs);
	if (result.error)
		return result.error;

	if (!aargs.rule.prefix6.set || !aargs.rule.prefix4.set || !aargs.rule.ea_bits_length.set) {
		struct requirement reqs[] = {
				{ aargs.rule.prefix6.set, "an IPv6 prefix" },
				{ aargs.rule.prefix4.set, "an IPv4 prefix" },
				{ aargs.rule.ea_bits_length.set, "an EA-bits Length value" },
				{ 0 },
		};
		return requirement_print(reqs);
	}

	fmr.prefix6 = aargs.rule.prefix6.prefix;
	fmr.prefix4 = aargs.rule.prefix4.prefix;
	fmr.ea_bits_length = aargs.rule.ea_bits_length.value;
	fmr.a = aargs.a.set ? aargs.a.value : 6;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joolnl_fmrt_add(&sk, iname, &fmr);

	joolnl_teardown(&sk);
	return pr_result(&result);
}

void autocomplete_fmrt_add(void const *args)
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
