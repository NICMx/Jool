#include "pool4.h"

#include "requirements.h"
#include "str-utils.h"
#include "usr-str-utils.h"
#include "userspace-types.h"
#include "wargp.h"
#include "netlink/pool4.h"

#define ARGP_MARK 3000
#define ARGP_MAX_ITERATIONS 3001
#define ARGP_QUICK 'q'
#define ARGP_FORCE 'f'

struct display_args {
	struct wargp_l4proto proto;
	struct wargp_bool no_headers;
	struct wargp_bool csv;

	unsigned int sample_count;
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

static void display_sample_csv(struct pool4_sample *sample,
		struct display_args *args)
{
	printf("%u,%s,%s,%u,%u,", sample->mark,
			l4proto_to_string(sample->proto),
			inet_ntoa(sample->range.addr),
			sample->range.ports.min,
			sample->range.ports.max);

	if (sample->iteration_flags & ITERATIONS_INFINITE) {
		printf("infinite,");
	} else {
		printf("%u,", sample->iterations);
	}

	printf("%u\n", !(sample->iteration_flags & ITERATIONS_AUTO));
}

static bool print_common_values(struct pool4_sample *sample,
		struct display_args *args)
{
	if (!args->last.initialized)
		return true;
	return sample->mark != args->last.mark
			|| sample->proto != args->last.proto;
}

static void print_table_divisor(void)
{
	/*
	 * Lol, dude. Maybe there's some console table manager library out there
	 * that we should be using.
	 */
	printf("+------------+-------+--------------------+-----------------+-------------+\n");
}

static void display_sample_normal(struct pool4_sample *sample,
		struct display_args *args)
{
	if (print_common_values(sample, args)) {
		print_table_divisor();

		printf("| %10u | %5s | ",
				sample->mark,
				l4proto_to_string(sample->proto));
		if (sample->iteration_flags & ITERATIONS_INFINITE)
			printf("%10s", "Infinite");
		else
			printf("%10u", sample->iterations);
		printf(" (%5s) | %15s | %5u-%5u |\n",
				(sample->iteration_flags & ITERATIONS_AUTO)
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

static int handle_display_response(struct pool4_sample *sample, void *args)
{
	struct display_args *dargs = args;

	if (dargs->csv.value)
		display_sample_csv(sample, args);
	else
		display_sample_normal(sample, args);

	dargs->sample_count++;
	return 0;
}

int handle_pool4_display(char *instance, int argc, char **argv)
{
	struct display_args dargs = { 0 };
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	if (!dargs.no_headers.value) {
		if (dargs.csv.value)
			printf("Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed\n");
		else {
			print_table_divisor();
			printf("|       Mark | Proto |     Max iterations |         Address |       Ports |\n");
		}
	}

	error = pool4_foreach(instance, dargs.proto.proto,
			handle_display_response, &dargs);
	if (error)
		return error;

	if (!dargs.csv.value)
		print_table_divisor();

	if (show_footer(dargs.no_headers.value, dargs.csv.value)) {
		if (dargs.sample_count > 0)
			log_info("  (Fetched %u samples.)", dargs.sample_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

void print_pool4_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}

struct parsing_entry {
	bool prefix4_set;
	struct pool4_entry_usr meat;
};

struct add_args {
	struct parsing_entry entry;
	struct wargp_l4proto proto;
	bool force;
};

static int parse_pool4_entry(void *void_field, int key, char *str)
{
	struct add_args *field = void_field;

	if (strchr(str, '.')) { /* Token is an IPv4 thingy. */
		field->entry.prefix4_set = true;
		return str_to_prefix4(str, &field->entry.meat.range.prefix);
	}

	/* Token is a port range. */
	return str_to_port_range(str, &field->entry.meat.range.ports);
}

struct wargp_type wt_pool4_entry = {
	.doc = "<IPv4 prefix> [<port range>]",
	.parse = parse_pool4_entry,
};

static struct wargp_option add_opts[] = {
	WARGP_TCP(struct add_args, proto, "Add the entry to the TCP table"),
	WARGP_UDP(struct add_args, proto, "Add the entry to the UDP table"),
	WARGP_ICMP(struct add_args, proto, "Add the entry to the ICMP table"),
	{
		.name = "mark",
		.key = ARGP_MARK,
		.doc = "", /* TODO */
		.offset = offsetof(struct add_args, entry.meat.mark),
		.type = &wt_u32,
	}, {
		.name = "max-iterations",
		.key = ARGP_MAX_ITERATIONS,
		.doc = "", /* TODO */
		.offset = offsetof(struct add_args, entry.meat.iterations),
		.type = &wt_u32,
	}, {
		.name = "force",
		.key = ARGP_FORCE,
		.doc = "", /* TODO */
		.offset = offsetof(struct add_args, force),
		.type = &wt_bool,
	}, {
		.name = "pool4 entry",
		.key = ARGP_KEY_ARG,
		.doc = "", /* TODO */
		.offset = offsetof(struct add_args, entry),
		.type = &wt_pool4_entry,
	},
	{ 0 },
};

int handle_pool4_add(char *instance, int argc, char **argv)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (!aargs.entry.prefix4_set) {
		struct requirement reqs[] = {
			{ aargs.entry.prefix4_set, "an IPv4 prefix or address" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	if (aargs.entry.meat.range.prefix.len < 24 && !aargs.force) {
		printf("Warning: You're adding lots of addresses, which "
				"might defeat the whole point of NAT64 over "
				"SIIT.\n");
		printf("Also, and more or less as a consequence, addresses are "
				"stored in a linked list. Having too many "
				"addresses in pool4 sharing a mark is slow.\n");
		printf("Consider using SIIT instead.\n");
		printf("Will cancel the operation. Use --force to override "
				"this.\n");
		return -E2BIG;
	}

	aargs.entry.meat.proto = aargs.proto.proto;
	return pool4_add(instance, &aargs.entry.meat);
}

void print_pool4_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
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
		.doc = "", /* TODO */
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
		.doc = "", /* TODO */
		.offset = offsetof(struct rm_args, entry),
		.type = &wt_pool4_entry,
	},
	{ 0 },
};

int handle_pool4_remove(char *instance, int argc, char **argv)
{
	struct rm_args rargs = { 0 };
	int error;

	error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (error)
		return error;

	if (!rargs.entry.prefix4_set) {
		struct requirement reqs[] = {
			{ rargs.entry.prefix4_set, "an IPv4 prefix or address" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	rargs.entry.meat.proto = rargs.proto.proto;
	return pool4_rm(instance, &rargs.entry.meat, rargs.quick);
}

void print_pool4_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
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

int handle_pool4_flush(char *instance, int argc, char **argv)
{
	struct flush_args fargs = { 0 };
	int error;

	error = wargp_parse(flush_opts, argc, argv, &fargs);
	if (error)
		return error;

	return pool4_flush(instance, fargs.quick);
}

void print_pool4_flush_opts(char *prefix)
{
	print_wargp_opts(flush_opts, prefix);
}
