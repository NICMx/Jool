#include "session.h"

#include <argp.h>

#include "constants.h"
#include "dns.h"
#include "nl-protocol.h"
#include "str-utils.h"
#include "userspace-types.h"
#include "usr-str-utils.h"
#include "netlink/session.h"

#define ARGP_TCP 't'
#define ARGP_UDP 'u'
#define ARGP_ICMP 'i'
#define ARGP_CSV 2003
#define ARGP_NO_HEADERS 2004

struct display_args {
	bool proto_set;
	l4_protocol proto;
	display_flags flags;
	unsigned int sample_count;
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

static int parse_proto(struct display_args *args, l4_protocol proto)
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
	struct display_args *args = state->input;

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

char *tcp_state_to_string(tcp_state state)
{
	switch (state) {
	case ESTABLISHED:
		return "ESTABLISHED";
	case V4_INIT:
		return "V4_INIT";
	case V6_INIT:
		return "V6_INIT";
	case V4_FIN_RCV:
		return "V4_FIN_RCV";
	case V6_FIN_RCV:
		return "V6_FIN_RCV";
	case V4_FIN_V6_FIN_RCV:
		return "V4_FIN_V6_FIN_RCV";
	case TRANS:
		return "TRANS";
	}

	return "UNKNOWN";
}

static int handle_display_response(struct session_entry_usr *entry, void *args)
{
	struct display_args *dargs = args;
	l4_protocol proto = dargs->proto;

	if (dargs->flags & DF_CSV_FORMAT) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->src6, dargs->flags, ",", proto);
		printf(",");
		print_addr6(&entry->dst6, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",");
		print_addr4(&entry->src4, DF_NUMERIC_HOSTNAME, ",", proto);
		printf(",");
		print_addr4(&entry->dst4, dargs->flags, ",", proto);
		printf(",");
		print_time_csv(entry->dying_time);
		if (proto == L4PROTO_TCP)
			printf(",%s", tcp_state_to_string(entry->state));
		printf("\n");
	} else {
		if (proto == L4PROTO_TCP)
			printf("(%s) ", tcp_state_to_string(entry->state));

		printf("Expires in ");
		print_time_friendly(entry->dying_time);

		printf("Remote: ");
		print_addr4(&entry->dst4, dargs->flags, "#", proto);
		printf("\t");
		print_addr6(&entry->src6, dargs->flags, "#", proto);
		printf("\n");

		printf("Local: ");
		print_addr4(&entry->src4, DF_NUMERIC_HOSTNAME, "#", proto);
		printf("\t");
		print_addr6(&entry->dst6, DF_NUMERIC_HOSTNAME, "#", proto);
		printf("\n");

		printf("---------------------------------\n");
	}

	return 0;
}

int handle_session_display(int argc, char **argv)
{
	static struct argp argp = { argp_display_opts, parse_display_opts, NULL, NULL };
	struct display_args dargs;
	int error;

	memset(&dargs, 0, sizeof(dargs));
	error = argp_parse(&argp, argc, argv, 0, NULL, &dargs);
	if (error)
		return error;

	if (!(dargs.flags & DF_CSV_FORMAT)) {
		printf("%s:\n", l4proto_to_string(dargs.proto));
		printf("---------------------------------\n");
	} else if (show_csv_header(dargs.flags)) {
		printf("Protocol,");
		printf("IPv6 Remote Address,IPv6 Remote L4-ID,");
		printf("IPv6 Local Address,IPv6 Local L4-ID,");
		printf("IPv4 Local Address,IPv4 Local L4-ID,");
		printf("IPv4 Remote Address,IPv4 Remote L4-ID,");
		printf("Expires in,State\n");
	}

	error = session_foreach(dargs.proto, handle_display_response, &dargs);

	if (show_footer(dargs.flags) && !error) {
		if (dargs.sample_count > 0)
			log_info("  (Fetched %u entries.)\n", dargs.sample_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}
