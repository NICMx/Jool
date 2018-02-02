#include "bib.h"

#include <argp.h>
#include <errno.h>

#include "dns.h"
#include "netlink.h"
#include "nl-protocol.h"
#include "str-utils.h"
#include "types.h"
#include "usr-str-utils.h"
#include "netlink/bib.h"

#define ARGP_TCP 't'
#define ARGP_UDP 'u'
#define ARGP_ICMP 'i'
#define ARGP_CSV 2003
#define ARGP_NO_HEADERS 2004

struct bib_argp_args {
	enum config_operation op;

	bool proto_set;
	l4_protocol proto;
	display_flags flags;

	bool addr6_set;
	struct ipv6_transport_addr addr6;
	bool addr4_set;
	struct ipv4_transport_addr addr4;
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

static struct argp_option argp_add_opts[] = {
	{
		.name = "tcp",
		.key = ARGP_TCP,
		.doc = "Add the entry to the TCP table.",
	},
	{
		.name = "udp",
		.key = ARGP_UDP,
		.doc = "Add the entry to the UDP table.",
	},
	{
		.name = "icmp",
		.key = ARGP_ICMP,
		.doc = "Add the entry to the ICMP table.",
	},
	{ 0 },
};

static struct argp_option argp_rm_opts[] = {
	{
		.name = "tcp",
		.key = ARGP_TCP,
		.doc = "Remove the entry from the TCP table.",
	},
	{
		.name = "udp",
		.key = ARGP_UDP,
		.doc = "Remove the entry from the UDP table.",
	},
	{
		.name = "icmp",
		.key = ARGP_ICMP,
		.doc = "Remove the entry from the ICMP table.",
	},
	{ 0 },
};

static int parse_proto(struct bib_argp_args *args, l4_protocol proto)
{
	if (args->proto_set && args->proto != proto) {
		log_err("Only one protocol is allowed per request.");
		return -EINVAL;
	}

	args->proto_set = true;
	args->proto = proto;
	return 0;
}

static int apply_flag(struct bib_argp_args *args, display_flags flag)
{
	if (args->op != OP_DISPLAY) {
		log_err("Display flags are only allowed during display operations.");
		return -EINVAL;
	}

	args->flags |= flag;
	return 0;
}

static int parse_taddr(struct bib_argp_args *args, char *str)
{
	if (args->op == OP_DISPLAY) {
		log_err("Unrecognized token: %s", str);
		return -EINVAL;
	}

	if (!str || strlen(str) == 0)
		return 0; /* TODO should be an error? */

	if (strchr(str, ':')) {
		args->addr6_set = true;
		return str_to_addr6_port(str, &args->addr6);
	}
	if (strchr(str, '.')) {
		args->addr4_set = true;
		return str_to_addr4_port(str, &args->addr4);
	}

	/* TODO error msg ?*/
	return -EINVAL;
}

static int parse_opts(int key, char *str, struct argp_state *state)
{
	struct bib_argp_args *args = state->input;

	switch (key) {
	case ARGP_TCP:
		return parse_proto(args, L4PROTO_TCP);
	case ARGP_UDP:
		return parse_proto(args, L4PROTO_UDP);
	case ARGP_ICMP:
		return parse_proto(args, L4PROTO_ICMP);
	case ARGP_CSV:
		return apply_flag(args, DF_CSV_FORMAT);
	case ARGP_NO_HEADERS:
		return apply_flag(args, DF_NO_HEADERS);
	case ARGP_KEY_ARG:
		return parse_taddr(args, str);
	}

	return ARGP_ERR_UNKNOWN;
}

static int print_entry(struct bib_entry_usr *entry, void *args)
{
	display_flags flags = *((display_flags *)args);
	l4_protocol proto = entry->l4_proto;

	if (flags & DF_CSV_FORMAT) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->addr6, flags, ",", proto);
		printf(",");
		print_addr4(&entry->addr4, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",%u\n", entry->is_static);
	} else {
		printf("[%s] ", entry->is_static ? "Static" : "Dynamic");
		print_addr4(&entry->addr4, DF_NUMERIC_HOSTNAME, "#", proto);
		printf(" - ");
		print_addr6(&entry->addr6, flags, "#", proto);
		printf("\n");
	}

	return 0;
}

void init_argp_args(struct bib_argp_args *args, enum config_operation op)
{
	memset(args, 0, sizeof(*args));
	args->op = op;
}

/*
 * BTW: This thing is not thread-safe because of the address-to-string v4
 * function.
 */
int handle_bib_display(int argc, char **argv)
{
	static struct argp argp = { argp_display_opts, parse_opts, NULL, NULL };
	struct bib_argp_args args;
	int error;

	init_argp_args(&args, OP_DISPLAY);
	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	if (show_csv_header(args.flags))
		printf("Protocol,IPv6 Address,IPv6 L4-ID,IPv4 Address,IPv4 L4-ID,Static?\n");

	return bib_foreach(args.proto, print_entry, &args.flags);
}

int handle_bib_add(int argc, char **argv)
{
	static struct argp argp = { argp_add_opts, parse_opts, NULL, NULL };
	struct bib_argp_args args;
	int error;

	init_argp_args(&args, OP_ADD);
	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	return bib_add(&args.addr6, &args.addr4, args.proto);
}

int handle_bib_remove(int argc, char **argv)
{
	static struct argp argp = { argp_rm_opts, parse_opts, NULL, NULL };
	struct bib_argp_args args;
	int error;

	init_argp_args(&args, OP_REMOVE);
	error = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (error)
		return error;

	return bib_rm(&args.addr6, &args.addr4, args.proto);
}
