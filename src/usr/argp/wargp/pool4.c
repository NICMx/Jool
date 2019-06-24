#include "pool4.h"

#include "log.h"
#include "usr/util/str_utils.h"
#include "usr/nl/jool_socket.h"
#include "usr/nl/pool4.h"
#include "usr/argp/log.h"
#include "usr/argp/requirements.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"

#define ARGP_MARK 3000
#define ARGP_MAX_ITERATIONS 3001
#define ARGP_QUICK 'q'

struct display_args {
	struct wargp_l4proto proto;
	struct wargp_bool no_headers;
	struct wargp_bool csv;

	struct {
		bool initialized;
		__u32 mark;
		__u8 proto;
	} last;
};

static struct wargp_option display_opts[] = {
	WARGP_TCP(struct display_args, proto, "Print the TCP table"),
	WARGP_UDP(struct display_args, proto, "Print the UDP table"),
	WARGP_ICMP(struct display_args, proto, "Print the ICMP table"),
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	{ 0 },
};

static void print_separator(void)
{
	print_table_separator(0, 10, 5, 18, 15, 11, 0);
}

static void display_sample_csv(struct pool4_sample *sample,
		struct display_args *args)
{
	printf("%u,%s,%s,%u,%u,", sample->mark,
			l4proto_to_string(sample->proto),
			inet_ntoa(sample->range.addr),
			sample->range.ports.min,
			sample->range.ports.max);

	if (sample->iterations_flags & ITERATIONS_INFINITE) {
		printf("infinite,");
	} else {
		printf("%u,", sample->iterations);
	}

	printf("%u\n", !(sample->iterations_flags & ITERATIONS_AUTO));
}

static bool print_common_values(struct pool4_sample *sample,
		struct display_args *args)
{
	if (!args->last.initialized)
		return true;
	return sample->mark != args->last.mark
			|| sample->proto != args->last.proto;
}

static void display_sample_normal(struct pool4_sample *sample,
		struct display_args *args)
{
	if (print_common_values(sample, args)) {
		print_separator();

		printf("| %10u | %5s | ",
				sample->mark,
				l4proto_to_string(sample->proto));
		if (sample->iterations_flags & ITERATIONS_INFINITE)
			printf("%10s", "Infinite");
		else
			printf("%10u", sample->iterations);
		printf(" (%5s) | %15s | %5u-%5u |\n",
				(sample->iterations_flags & ITERATIONS_AUTO)
						? "auto"
						: "fixed",
				inet_ntoa(sample->range.addr),
				sample->range.ports.min,
				sample->range.ports.max);
	} else {
		printf("| %10s | %5s | %10s  %5s  | %15s | %5u-%5u |\n",
				"",
				"",
				"",
				"",
				inet_ntoa(sample->range.addr),
				sample->range.ports.min,
				sample->range.ports.max);
	}

	args->last.initialized = true;
	args->last.mark = sample->mark;
	args->last.proto = sample->proto;
}

static struct jool_result handle_display_response(struct pool4_sample *sample,
		void *args)
{
	struct display_args *dargs = args;

	if (dargs->csv.value)
		display_sample_csv(sample, args);
	else
		display_sample_normal(sample, args);

	return result_success();
}

int handle_pool4_display(char *iname, int argc, char **argv, void *arg)
{
	struct display_args dargs = { 0 };
	struct jool_socket sk;
	struct jool_result result;

	result.error = wargp_parse(display_opts, argc, argv, &dargs);
	if (result.error)
		return result.error;

	result = netlink_setup(&sk);
	if (result.error)
		return log_result(&result);

	if (!dargs.no_headers.value) {
		if (dargs.csv.value)
			printf("Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed\n");
		else {
			print_separator();
			printf("| %10s | %5s | %18s | %15s | %11s |\n",
					"Mark", "Proto", "Max iterations",
					"Address", "Ports");
		}
	}

	result = pool4_foreach(&sk, iname, dargs.proto.proto,
			handle_display_response, &dargs);

	netlink_teardown(&sk);

	if (result.error)
		return log_result(&result);

	if (!dargs.csv.value)
		print_separator();
	return 0;
}

void autocomplete_pool4_display(void *args)
{
	print_wargp_opts(display_opts);
}

struct parsing_entry {
	bool prefix4_set;
	bool range_set;
	struct pool4_entry_usr meat;
};

struct add_args {
	struct parsing_entry entry;
	struct wargp_l4proto proto;
	bool force;
};

static int parse_max_iterations(void *void_field, int key, char *str)
{
	struct pool4_entry_usr *meat = void_field;
	struct jool_result result;

	meat->flags = ITERATIONS_SET;

	if (STR_EQUAL(str, "auto")) {
		meat->flags |= ITERATIONS_AUTO;
		return 0;
	}
	if (STR_EQUAL(str, "infinity")) {
		meat->flags |= ITERATIONS_INFINITE;
		return 0;
	}

	result = str_to_u32(str, &meat->iterations, 0, MAX_U32);
	return log_result(&result);
}

struct wargp_type wt_max_iterations = {
	.argument = "(<integer>|auto|infinity)",
	.parse = parse_max_iterations,
	.candidates = "auto infinity",
};

static int parse_pool4_entry(void *void_field, int key, char *str)
{
	struct add_args *field = void_field;
	struct jool_result result;

	if (strchr(str, '.')) { /* Token is an IPv4 thingy. */
		field->entry.prefix4_set = true;
		result = str_to_prefix4(str, &field->entry.meat.range.prefix);
		return log_result(&result);
	}

	/* Token is a port range. */
	field->entry.range_set = true;
	result = str_to_port_range(str, &field->entry.meat.range.ports);
	return log_result(&result);
}

struct wargp_type wt_pool4_entry = {
	.argument = "<IPv4 prefix> [<port range>]",
	.parse = parse_pool4_entry,
};

static struct wargp_option add_opts[] = {
	WARGP_TCP(struct add_args, proto, "Add the entry to the TCP table"),
	WARGP_UDP(struct add_args, proto, "Add the entry to the UDP table"),
	WARGP_ICMP(struct add_args, proto, "Add the entry to the ICMP table"),
	{
		.name = "mark",
		.key = ARGP_MARK,
		.doc = "In the IPv6 to IPv4 direction, only packets carrying this mark will match this pool4 entry",
		.offset = offsetof(struct add_args, entry.meat.mark),
		.type = &wt_u32,
	}, {
		.name = "max-iterations",
		.key = ARGP_MAX_ITERATIONS,
		.doc = "Maximum number of times the transport address lookup algorithm should be allowed to iterate\n"
				"(This algorithm is used to find an available transport address to create a BIB entry with)",
		.offset = offsetof(struct add_args, entry.meat),
		.type = &wt_max_iterations,
	},
	WARGP_FORCE(struct add_args, force),
	{
		.name = "pool4 entry",
		.key = ARGP_KEY_ARG,
		.doc = "Range of transport addresses that should be reserved for translation",
		.offset = offsetof(struct add_args, entry),
		.type = &wt_pool4_entry,
	},
	{ 0 },
};

int handle_pool4_add(char *iname, int argc, char **argv, void *arg)
{
	struct add_args aargs = { 0 };
	struct jool_socket sk;
	struct jool_result result;

	result.error = wargp_parse(add_opts, argc, argv, &aargs);
	if (result.error)
		return result.error;

	if (!aargs.entry.prefix4_set
			|| !aargs.entry.range_set
			|| !aargs.proto.set) {
		struct requirement reqs[] = {
			{ aargs.entry.prefix4_set, "an IPv4 prefix or address" },
			{ aargs.entry.range_set, "a port (or ICMP id) range" },
			{ aargs.proto.set, "a protocol (--tcp, --udp or --icmp)" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	if (aargs.entry.meat.range.prefix.len < 24 && !aargs.force) {
		log_err("Warning: You're adding lots of addresses, which might defeat the whole point of NAT64 over SIIT.");
		log_err("Will cancel the operation. Use --force to override this.");
		return -E2BIG;
	}

	aargs.entry.meat.proto = aargs.proto.proto;

	result = netlink_setup(&sk);
	if (result.error)
		return log_result(&result);

	result = pool4_add(&sk, iname, &aargs.entry.meat);

	netlink_teardown(&sk);
	return log_result(&result);
}

void autocomplete_pool4_add(void *args)
{
	print_wargp_opts(add_opts);
}

struct rm_args {
	struct parsing_entry entry;
	struct wargp_l4proto proto;
	bool quick;
};

static struct wargp_option remove_opts[] = {
	WARGP_TCP(struct add_args, proto,
			"Remove the entry from the TCP table"),
	WARGP_UDP(struct add_args, proto,
			"Remove the entry from the UDP table"),
	WARGP_ICMP(struct add_args, proto,
			"Remove the entry from the ICMP table"),
	{
		.name = "mark",
		.key = ARGP_MARK,
		.doc = "Only remove entries that match this mark",
		.offset = offsetof(struct rm_args, entry.meat.mark),
		.type = &wt_u32,
	}, {
		.name = "quick",
		.key = ARGP_QUICK,
		.doc = "Do not cascade removal to BIB entries",
		.offset = offsetof(struct rm_args, quick),
		.type = &wt_bool,
	}, {
		.name = "pool4 entry",
		.key = ARGP_KEY_ARG,
		.doc = "Range of transport addresses that should no longer be reserved for translation",
		.offset = offsetof(struct rm_args, entry),
		.type = &wt_pool4_entry,
	},
	{ 0 },
};

int handle_pool4_remove(char *iname, int argc, char **argv, void *arg)
{
	struct rm_args rargs = { 0 };
	struct jool_socket sk;
	struct jool_result result;

	result.error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (result.error)
		return result.error;

	if (!rargs.entry.prefix4_set) {
		struct requirement reqs[] = {
			{ rargs.entry.prefix4_set, "an IPv4 prefix or address" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	rargs.entry.meat.proto = rargs.proto.proto;

	result = netlink_setup(&sk);
	if (result.error)
		return log_result(&result);

	result = pool4_rm(&sk, iname, &rargs.entry.meat, rargs.quick);

	netlink_teardown(&sk);
	return log_result(&result);
}

void autocomplete_pool4_remove(void *args)
{
	print_wargp_opts(remove_opts);
}

struct flush_args {
	bool quick;
};

static struct wargp_option flush_opts[] = {
	{
		.name = "quick",
		.key = ARGP_QUICK,
		.doc = "Do not cascade removal to BIB entries",
		.offset = offsetof(struct flush_args, quick),
		.type = &wt_bool,
	},
	{ 0 },
};

int handle_pool4_flush(char *iname, int argc, char **argv, void *arg)
{
	struct flush_args fargs = { 0 };
	struct jool_socket sk;
	struct jool_result result;

	result.error = wargp_parse(flush_opts, argc, argv, &fargs);
	if (result.error)
		return result.error;

	result = netlink_setup(&sk);
	if (result.error)
		return log_result(&result);

	result = pool4_flush(&sk, iname, fargs.quick);

	netlink_teardown(&sk);
	return log_result(&result);
}

void autocomplete_pool4_flush(void *args)
{
	print_wargp_opts(flush_opts);
}
