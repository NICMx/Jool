#include "pool4.h"

#include <argp.h>

#include "nl-protocol.h"
#include "str-utils.h"
#include "usr-str-utils.h"
#include "userspace-types.h"
#include "netlink/pool4.h"

#define ARGP_TCP 't'
#define ARGP_UDP 'u'
#define ARGP_ICMP 'i'
#define ARGP_CSV 2003
#define ARGP_NO_HEADERS 2004

#define ARGP_MARK 2000
#define ARGP_MAX_ITERATIONS 2001
#define ARGP_QUICK 2002
#define ARGP_FORCE 2002

struct parsing_entry {
	bool prefix4_set;
	struct pool4_entry_usr meat;
};

struct pool4_display_argp_args {
	bool proto_set;
	l4_protocol proto;

	display_flags flags;

	unsigned int sample_count;

	struct {
		bool initialized;
		__u32 mark;
		__u8 proto;
	} last;
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
	{
		.name = "tcp",
		.key = ARGP_TCP,
		.doc = "Print the TCP table.",
	},
	{
		.name = "udp",
		.key = ARGP_UDP,
		.doc = "Print the UDP table.",
	},
	{
		.name = "icmp",
		.key = ARGP_ICMP,
		.doc = "Print the ICMP table.",
	},
	{ 0 },
};

static int parse_proto(struct pool4_display_argp_args *args, l4_protocol proto)
{
	if (args->proto_set && args->proto != proto) {
		log_err("Only one protocol is allowed per request.");
		return -EINVAL;
	}

	args->proto_set = true;
	args->proto = proto;
	return 0;
}

static int parse_display_opts(int key, char *str, struct argp_state *state)
{
	struct pool4_display_argp_args *args = state->input;

	switch (key) {
	case ARGP_TCP:
		return parse_proto(args, L4PROTO_TCP);
	case ARGP_UDP:
		return parse_proto(args, L4PROTO_UDP);
	case ARGP_ICMP:
		return parse_proto(args, L4PROTO_ICMP);
	case ARGP_CSV:
		args->flags |= DF_CSV_FORMAT;
		return 0;
	case ARGP_NO_HEADERS:
		args->flags |= DF_NO_HEADERS;
	}

	return ARGP_ERR_UNKNOWN;
}

static void display_sample_csv(struct pool4_sample *sample,
		struct pool4_display_argp_args *args)
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
		struct pool4_display_argp_args *args)
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
		struct pool4_display_argp_args *args)
{
	if (print_common_values(sample, args)) {
		print_table_divisor();

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

static int handle_display_response(struct pool4_sample *sample, void *args)
{
	struct pool4_display_argp_args *dargs = args;

	if (dargs->flags & DF_CSV_FORMAT)
		display_sample_csv(sample, args);
	else
		display_sample_normal(sample, args);

	dargs->sample_count++;
	return 0;
}

int handle_pool4_display(int argc, char **argv)
{
	static struct argp argp = { argp_display_opts, parse_display_opts, NULL, NULL };
	struct pool4_display_argp_args dargs;
	int error;

	memset(&dargs, 0, sizeof(dargs));
	error = argp_parse(&argp, argc, argv, 0, NULL, &dargs);
	if (error)
		return error;

	if (!(dargs.flags & DF_NO_HEADERS)) {
		if (dargs.flags & DF_CSV_FORMAT)
			printf("Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed\n");
		else {
			print_table_divisor();
			printf("|       Mark | Proto |     Max iterations |         Address |       Ports |\n");
		}
	}

	error = pool4_foreach(dargs.proto, handle_display_response, &dargs);
	if (error)
		return error;

	if (!(dargs.flags & DF_CSV_FORMAT))
		print_table_divisor();

	if (show_footer(dargs.flags)) {
		if (dargs.sample_count > 0)
			log_info("  (Fetched %u samples.)", dargs.sample_count);
		else
			log_info("  (empty)");
	}

	return 0;
}

static int parse_pool4_entry(struct parsing_entry *entry, char *str)
{
	if (!str || strlen(str) == 0) /* TODO */
		return 0;

	if (strchr(str, '.')) { /* Token is an IPv4 thingy. */
		entry->prefix4_set = true;
		return str_to_prefix4(str, &entry->meat.range.prefix);
	}

	/* Token is a port range. */
	return str_to_port_range(str, &entry->meat.range.ports);
}

static struct argp_option argp_add_opts[] = {
	{
		.name = "mark",
		.key = ARGP_MARK,
		.doc = "", /* TODO */
	},
	{
		.name = "max-iterations",
		.key = ARGP_MAX_ITERATIONS,
		.doc = "", /* TODO */
	},
	{
		.name = "force",
		.key = ARGP_FORCE,
		.doc = "", /* TODO */
	},
	{ 0 },
};

struct pool4_add_argp_args {
	struct parsing_entry entry;
	bool force;
};

static int parse_add_opts(int key, char *str, struct argp_state *state)
{
	struct pool4_add_argp_args *args = state->input;

	switch (key) {
	case ARGP_MARK:
		return str_to_u32(str, &args->entry.meat.mark, 0, 0xFFFFFFFF);
	case ARGP_MAX_ITERATIONS:
		return str_to_u32(str, &args->entry.meat.iterations, 0, 0xFFFFFFFF);
	case ARGP_FORCE:
		args->force = true;
		return 0;
	case ARGP_KEY_ARG:
		return parse_pool4_entry(&args->entry, str);
	}

	return ARGP_ERR_UNKNOWN;
}

int handle_pool4_add(int argc, char **argv)
{
	static struct argp argp = { argp_add_opts, parse_add_opts, NULL, NULL };
	struct pool4_add_argp_args args = { 0 };
	int error;

	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	if (!args.entry.prefix4_set) {
		log_err("Expected an IPv4 address or prefix.");
		return -EINVAL;
	}

	if (args.entry.meat.range.prefix.len < 24 && !args.force) {
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

	return pool4_add(&args.entry.meat, args.force);
}

//int handle_pool4_update(int argc, char **argv)
//{
//
//}

static struct argp_option argp_rm_opts[] = {
	{
		.name = "quick",
		.key = ARGP_QUICK,
		.doc = "Do not cascade removal to BIB entries.",
	},
	{ 0 },
};

struct pool4_rm_argp_args {
	struct parsing_entry entry;
	bool quick;
};

static int parse_rm_opts(int key, char *str, struct argp_state *state)
{
	struct pool4_rm_argp_args *args = state->input;

	switch (key) {
	case ARGP_MARK:
		return str_to_u32(str, &args->entry.meat.mark, 0, 0xFFFFFFFF);
	case ARGP_QUICK:
		args->quick = true;
		return 0;
	case ARGP_KEY_ARG:
		return parse_pool4_entry(&args->entry, str);
	}

	return ARGP_ERR_UNKNOWN;
}

int handle_pool4_rm(int argc, char **argv)
{
	static struct argp argp = { argp_rm_opts, parse_rm_opts, NULL, NULL };
	struct pool4_rm_argp_args args = { 0 };
	int error;

	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	return pool4_rm(&args.entry.meat, args.quick);
}

static struct argp_option argp_flush_opts[] = {
	{
		.name = "quick",
		.key = ARGP_QUICK,
		.doc = "Do not cascade removal to BIB entries.",
	},
	{ 0 },
};

struct pool4_flush_argp_args {
	bool quick;
};

static int parse_flush_opts(int key, char *str, struct argp_state *state)
{
	struct pool4_flush_argp_args *args = state->input;

	switch (key) {
	case ARGP_QUICK:
		args->quick = true;
		return 0;
	}

	return ARGP_ERR_UNKNOWN;
}

int handle_pool4_flush(int argc, char **argv)
{
	static struct argp argp = { argp_flush_opts, parse_flush_opts, NULL, NULL };
	struct pool4_flush_argp_args args = { 0 };
	int error;

	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	return pool4_flush(args.quick);
}
