#include "bib.h"

#include "dns.h"
#include "requirements.h"
#include "str-utils.h"
#include "usr-str-utils.h"
#include "wargp.h"
#include "netlink/bib.h"

struct display_args {
	struct wargp_l4proto proto;
	struct wargp_bool no_headers;
	struct wargp_bool csv;
	struct wargp_bool numeric;
};

static struct wargp_option display_opts[] = {
	WARGP_TCP(struct display_args, proto, "Print the TCP table"),
	WARGP_UDP(struct display_args, proto, "Print the UDP table"),
	WARGP_ICMP(struct display_args, proto, "Print the ICMP table"),
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	WARGP_NUMERIC(struct display_args, numeric),
	{ 0 },
};

static int print_entry(struct bib_entry_usr *entry, void *args)
{
	struct display_args *dargs = args;
	l4_protocol proto = entry->proto;

	if (dargs->csv.value) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->addr6, dargs->numeric.value, ",", proto);
		printf(",");
		print_addr4(&entry->addr4, true, ",", proto);
		printf(",%u\n", entry->is_static);
	} else {
		printf("[%s %s] ", entry->is_static ? "Static" : "Dynamic",
				l4proto_to_string(proto));
		print_addr4(&entry->addr4, true, "#", proto);
		printf(" - ");
		print_addr6(&entry->addr6, dargs->numeric.value, "#", proto);
		printf("\n");
	}

	return 0;
}

/*
 * BTW: This thing is not thread-safe because of the address-to-string v4
 * function.
 */
int handle_bib_display(char *instance, int argc, char **argv)
{
	struct display_args dargs = { 0 };
	int error;

	error = wargp_parse(display_opts, argc, argv, &dargs);
	if (error)
		return error;

	if (show_csv_header(dargs.no_headers.value, dargs.csv.value))
		printf("Protocol,IPv6 Address,IPv6 L4-ID,IPv4 Address,IPv4 L4-ID,Static?\n");

	return bib_foreach(instance, dargs.proto.proto, print_entry, &dargs);
}

void print_bib_display_opts(char *prefix)
{
	print_wargp_opts(display_opts, prefix);
}

struct taddr_tuple {
	bool addr6_set;
	struct ipv6_transport_addr addr6;
	bool addr4_set;
	struct ipv4_transport_addr addr4;
};

static int parse_taddr(void *void_field, int key, char *str)
{
	struct taddr_tuple *field = void_field;

	if (strchr(str, ':')) {
		field->addr6_set = true;
		return str_to_addr6_port(str, &field->addr6);
	}
	if (strchr(str, '.')) {
		field->addr4_set = true;
		return str_to_addr4_port(str, &field->addr4);
	}

	return ARGP_ERR_UNKNOWN;
}

struct add_args {
	struct wargp_l4proto proto;
	struct taddr_tuple taddrs;
};

struct wargp_type wt_taddr = {
	.doc = "<IPv6 transport address> <IPv4 transport address>",
	.parse = parse_taddr,
};

static struct wargp_option add_opts[] = {
	WARGP_TCP(struct add_args, proto, "Add the entry to the TCP table"),
	WARGP_UDP(struct add_args, proto, "Add the entry to the UDP table"),
	WARGP_ICMP(struct add_args, proto, "Add the entry to the ICMP table"),
	{
		.name = "Transport addresses",
		.key = ARGP_KEY_ARG,
		.doc = "Transport addresses that shape the BIB entry you want to add",
		.offset = offsetof(struct add_args, taddrs),
		.type = &wt_taddr,
	},
	{ 0 },
};

int handle_bib_add(char *instance, int argc, char **argv)
{
	struct add_args aargs = { 0 };
	int error;

	error = wargp_parse(add_opts, argc, argv, &aargs);
	if (error)
		return error;

	if (!aargs.taddrs.addr6_set || !aargs.taddrs.addr4_set) {
		struct requirement reqs[] = {
			{ aargs.taddrs.addr6_set, "an IPv6 transport address" },
			{ aargs.taddrs.addr4_set, "an IPv4 transport address" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	return bib_add(instance, &aargs.taddrs.addr6, &aargs.taddrs.addr4,
			aargs.proto.proto);
}

void print_bib_add_opts(char *prefix)
{
	print_wargp_opts(add_opts, prefix);
}

struct rm_args {
	struct wargp_l4proto proto;
	struct taddr_tuple taddrs;
};

static struct wargp_option remove_opts[] = {
	WARGP_TCP(struct rm_args, proto, "Remove the entry from the TCP table"),
	WARGP_UDP(struct rm_args, proto, "Remove the entry from the UDP table"),
	WARGP_ICMP(struct rm_args, proto, "Remove the entry from the ICMP table"),
	{
		.name = "Transport addresses",
		.key = ARGP_KEY_ARG,
		.doc = "Transport addresses that shape the BIB entry you want to remove",
		.offset = offsetof(struct rm_args, taddrs),
		.type = &wt_taddr,
	},
	{ 0 },
};

int handle_bib_remove(char *instance, int argc, char **argv)
{
	struct rm_args rargs = { 0 };
	int error;

	error = wargp_parse(remove_opts, argc, argv, &rargs);
	if (error)
		return error;

	if (!rargs.taddrs.addr6_set && !rargs.taddrs.addr4_set) {
		struct requirement reqs[] = {
			{ rargs.taddrs.addr6_set || rargs.taddrs.addr4_set,
					"at least one transport address" },
			{ 0 },
		};
		return requirement_print(reqs);
	}

	return bib_rm(instance,
			rargs.taddrs.addr6_set ? &rargs.taddrs.addr6 : NULL,
			rargs.taddrs.addr4_set ? &rargs.taddrs.addr4 : NULL,
			rargs.proto.proto);
}

void print_bib_remove_opts(char *prefix)
{
	print_wargp_opts(remove_opts, prefix);
}
