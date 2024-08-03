#include "usr/argp/wargp/session.h"

#include <linux/types.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <syslog.h>

#include "common/config.h"
#include "common/constants.h"
#include "common/session.h"
#include "usr/util/str_utils.h"
#include "usr/nl/core.h"
#include "usr/nl/joold.h"
#include "usr/nl/session.h"
#include "usr/argp/dns.h"
#include "usr/argp/log.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"
#include "usr/argp/joold/modsocket.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
	struct wargp_bool numeric;
	struct wargp_l4proto proto;
};

static struct wargp_option display_opts[] = {
	WARGP_TCP(struct display_args, proto, "Print the TCP table (default)"),
	WARGP_UDP(struct display_args, proto, "Print the UDP table"),
	WARGP_ICMP(struct display_args, proto, "Print the ICMP table"),
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	WARGP_NUMERIC(struct display_args, numeric),
	{ 0 },
};

static char *tcp_state_to_string(tcp_state state)
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

static struct jool_result handle_display_response(
		struct session_entry_usr const *entry, void *args)
{
	struct display_args *dargs = args;
	l4_protocol proto = dargs->proto.proto;
	char timeout[TIMEOUT_BUFLEN];

	timeout2str(entry->dying_time, timeout);

	if (dargs->csv.value) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->src6, dargs->numeric.value, ",", proto);
		printf(",");
		print_addr6(&entry->dst6, true, ",", proto);
		printf(",");
		print_addr4(&entry->src4, true, ",", proto);
		printf(",");
		print_addr4(&entry->dst4, dargs->numeric.value, ",", proto);
		printf(",");
		printf("%s", timeout);
		if (proto == L4PROTO_TCP)
			printf(",%s", tcp_state_to_string(entry->state));
		printf("\n");
	} else {
		if (proto == L4PROTO_TCP)
			printf("(%s) ", tcp_state_to_string(entry->state));

		printf("Expires in %s\n", timeout);

		printf("Remote: ");
		print_addr4(&entry->dst4, dargs->numeric.value, "#", proto);
		printf("\t");
		print_addr6(&entry->src6, dargs->numeric.value, "#", proto);
		printf("\n");

		printf("Local: ");
		print_addr4(&entry->src4, true, "#", proto);
		printf("\t");
		print_addr6(&entry->dst6, true, "#", proto);
		printf("\n");

		printf("---------------------------------\n");
	}

	return result_success();
}

int handle_session_display(char *iname, int argc, char **argv, void const *arg)
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

	if (!dargs.csv.value) {
		printf("---------------------------------\n");
	} else if (show_csv_header(dargs.no_headers.value, dargs.csv.value)) {
		printf("Protocol,");
		printf("IPv6 Remote Address,IPv6 Remote L4-ID,");
		printf("IPv6 Local Address,IPv6 Local L4-ID,");
		printf("IPv4 Local Address,IPv4 Local L4-ID,");
		printf("IPv4 Remote Address,IPv4 Remote L4-ID,");
		printf("Expires in,State\n");
	}

	result = joolnl_session_foreach(&sk, iname, dargs.proto.proto,
			handle_display_response, &dargs);

	joolnl_teardown(&sk);

	return pr_result(&result);
}

int handle_session_follow(char *iname, int argc, char **argv, void const *arg)
{
	int error;

	error = wargp_parse(NULL, argc, argv, NULL);
	if (error)
		return error;

	openlog("joold", 0, LOG_DAEMON);

	error = modsocket_setup(iname);
	if (error)
		goto end;

	modsocket_listen(NULL);

end:	closelog();
	return error;
}

struct proxy_args {
	struct wargp_string net_mcast_addr;
	struct wargp_string net_mcast_port;
	struct wargp_string net_dev_in;
	struct wargp_string net_dev_out;
	__u32 net_ttl;
	struct wargp_string stats_addr;
	struct wargp_string stats_port;
};

static struct wargp_option proxy_opts[] = {
	{
		.name = "net.mcast.address",
		.key = ARGP_KEY_ARG,
		.doc = "Address where the sessions will be advertised",
		.offset = offsetof(struct proxy_args, net_mcast_addr),
		.type = &wt_string,
		.arg = "<net.mcast.address>"
	}, {
		.name = "net.mcast.port",
		.key = 'p',
		.doc = "UDP port where the sessions will be advertised",
		.offset = offsetof(struct proxy_args, net_mcast_port),
		.type = &wt_string,
	}, {
		.name = "net.dev.in",
		.key = 'i',
		.doc = "IPv4: IP_ADD_MEMBERSHIP; IPv6: IPV6_ADD_MEMBERSHIP (see ip(7))",
		.offset = offsetof(struct proxy_args, net_dev_in),
		.type = &wt_string,
	}, {
		.name = "net.dev.out",
		.key = 'o',
		.doc = "IPv4: IP_MULTICAST_IF, IPv6: IPV6_MULTICAST_IF (see ip(7))",
		.offset = offsetof(struct proxy_args, net_dev_out),
		.type = &wt_string,
	}, {
		.name = "net.ttl",
		.key = 't',
		.doc = "Multicast datagram Time To Live",
		.offset = offsetof(struct proxy_args, net_ttl),
		.type = &wt_u32,
	}, {
		.name = "stats.address",
		.key = 3010,
		.doc = "Address to bind the stats socket to",
		.offset = offsetof(struct proxy_args, stats_addr),
		.type = &wt_string,
	}, {
		.name = "stats.port",
		.key = 3011,
		.doc = "Port to bind the stats socket to",
		.offset = offsetof(struct proxy_args, stats_port),
		.type = &wt_string,
	},
	{ 0 },
};

int handle_session_proxy(char *iname, int argc, char **argv, void const *arg)
{
	struct proxy_args pargs = { 0 };
	struct netsocket_cfg netcfg;
	struct statsocket_cfg statcfg;
	int error;

	pargs.net_ttl = 1;

	error = wargp_parse(proxy_opts, argc, argv, &pargs);
	if (error)
		return error;

	netcfg.enabled = true;
	netcfg.mcast_addr = pargs.net_mcast_addr.value;
	netcfg.mcast_port = (pargs.net_mcast_port.value != NULL)
			? pargs.net_mcast_port.value
			: "6400";
	netcfg.in_interface = pargs.net_dev_in.value;
	netcfg.out_interface = pargs.net_dev_out.value;
	netcfg.ttl = pargs.net_ttl;

	statcfg.enabled = pargs.stats_addr.value || pargs.stats_port.value;
	statcfg.address = (pargs.stats_addr.value != NULL)
			? pargs.stats_addr.value
			: "::";
	statcfg.port = (pargs.stats_port.value != NULL)
			? pargs.stats_port.value
			: "6401";

	return joold_start(iname, &netcfg, &statcfg);
}

int handle_session_advertise(char *iname, int argc, char **argv, void const *arg)
{
	struct joolnl_socket sk;
	struct jool_result result;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joolnl_joold_advertise(&sk, iname);

	joolnl_teardown(&sk);
	return pr_result(&result);
}

void autocomplete_session_display(void const *args)
{
	print_wargp_opts(display_opts);
}

void autocomplete_session_follow(void const *args)
{
	/* Nothing needed here. */
}

void autocomplete_session_proxy(void const *args)
{
	print_wargp_opts(proxy_opts);
}

void autocomplete_session_advertise(void const *args)
{
	/* Nothing needed here. */
}

int joold_start(char const *iname, struct netsocket_cfg *netcfg,
		struct statsocket_cfg *statcfg)
{
	int error;

	iname = iname ? iname : "default";

	printf("Config:\n");
	printf("  mod.instance: %s\n", iname);
	if (netcfg->enabled) {
		printf("  net.mcast.addr: %s\n", netcfg->mcast_addr);
		printf("  net.mcast.port: %s\n", netcfg->mcast_port);
		printf("  net.dev.in: %s\n", netcfg->in_interface);
		printf("  net.dev.out: %s\n", netcfg->out_interface);
		printf("  net.ttl: %d\n", netcfg->ttl);
	}
	if (statcfg->enabled) {
		printf("  stats.addr: %s\n", statcfg->address);
		printf("  stats.port: %s\n", statcfg->port);
	}

	printf("\n");
	printf("joold is intended as a daemon, so it outputs straight to syslog.\n");
	printf("The standard streams will mostly shut up from now on.\n");
	printf("---------------------------------------------\n");

	openlog("joold", 0, LOG_DAEMON);

	error = modsocket_setup(iname);
	if (error)
		goto end;
	error = netsocket_start(netcfg);
	if (error)
		goto end;
	error = statsocket_start(statcfg);
	if (error)
		goto end;

	modsocket_listen(NULL); /* Loops forever */

end:	closelog();
	fprintf(stderr, "joold error: %d (See syslog)\n", error);
	return error;
}
