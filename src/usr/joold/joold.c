#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "log.h"
#include "common/types.h"
#include "common/xlat.h"
#include "usr/joold/modsocket.h"
#include "usr/joold/netsocket.h"
#include "usr/joold/statsocket.h"

static const struct option OPTIONS[] = {
	{
		.name = "version",
		.has_arg = no_argument,
		.val = 'V',
	}, {
		.name = "help",
		.has_arg = no_argument,
		.val = 'h',
	},

	/* Files */

	{
		.name = "modsocket",
		.has_arg = required_argument,
		.val = 'm',
	}, {
		.name = "netsocket",
		.has_arg = required_argument,
		.val = 'n',
	}, {
		.name = "statsocket",
		.has_arg = required_argument,
		.val = 's',
	},

	/* Modsocket */

	{
		.name = "instance",
		.has_arg = required_argument,
		.val = 'i',
	},

	/* Netsocket */

	{
		.name = "--net.multicast.addr",
		.has_arg = required_argument,
		.val = 1100,
	}, {
		.name = "--net.multicast.port",
		.has_arg = required_argument,
		.val = 1101,
	}, {
		.name = "--net.interface.in",
		.has_arg = required_argument,
		.val = 1102,
	}, {
		.name = "--net.interface.out",
		.has_arg = required_argument,
		.val = 1103,
	}, {
		.name = "--net.ttl",
		.has_arg = required_argument,
		.val = 1104,
	},

	/* Statsocket */

	{
		.name = "stats.address",
		.has_arg = required_argument,
		.val = 1200,
	}, {
		.name = "stats.port",
		.has_arg = required_argument,
		.val = 1201,
	},
	{ 0 },
};

static void print_help(void)
{
	printf("-V, --version              Print program version number\n");
	printf("-h, --help                 Print this\n\n");

	printf("-m, --modsocket=FILE       Path to file containing kernel socket config\n");
	printf("-n, --netsocket=FILE       Path to file containing network socket config\n");
	printf("-s, --statsocket=FILE      Path to file containing stats socket config\n\n");

	printf("-i, --instance=STRING      Kernelspace Jool instance name\n");
	printf("                           (Default: \"default\")\n\n");

	printf("--net.multicast.addr=ADDR  Address where the sessions will be advertised\n");
	printf("--net.multicast.port=STR   UDP port where the sessions will be advertised\n");
	printf("--net.interface.in=STR     IPv4: IP_ADD_MEMBERSHIP; IPv6: IPV6_ADD_MEMBERSHIP\n");
	printf("                           (see ip(7))\n");
	printf("--net.interface.out=STR    IPv4: IP_MULTICAST_IF, IPv6: IPV6_MULTICAST_IF\n");
	printf("                           (see ip(7))\n");
	printf("--net.ttl=INT              Multicast datagram Time To Live\n\n");

	printf("--stats.address=ADDR       Address to bind the stats socket to\n");
	printf("--stats.port=INT           Port to bind the stats socket to\n");
}

int main(int argc, char **argv)
{
	char const *OPTS = "Vhm:n:s:i:";
	int opt;
	unsigned long ul;
	int error;

	modcfg.iname = "default";
	netcfg.ttl = 1;

	while ((opt = getopt_long(argc, argv, OPTS, OPTIONS, NULL)) != -1) {
		switch (opt) {
		case 'V':
			printf(JOOL_VERSION_STR "\n");
			return 0;
		case 'h':
			print_help();
			return 0;

		case 'm':
			error = modsocket_config(optarg);
			if (error)
				return error;
			break;
		case 'n':
			error = netsocket_config(optarg);
			if (error)
				return error;
			break;
		case 's':
			error = statsocket_config(optarg);
			if (error)
				return error;
			break;

		case 'i':
			modcfg.iname = optarg;
			break;

		case 1100:
			netcfg.enabled = true;
			netcfg.mcast_addr = optarg;
			break;
		case 1101:
			netcfg.enabled = true;
			netcfg.mcast_port = optarg;
			break;

		case 1102:
			netcfg.enabled = true;
			netcfg.in_interface = optarg;
			break;
		case 1103:
			netcfg.enabled = true;
			netcfg.out_interface = optarg;
			break;
		case 1104:
			netcfg.enabled = true;
			errno = 0;
			ul = strtoul(optarg, NULL, 10);
			if (ul > 255 || errno) {
				syslog(LOG_ERR, "ttl out of range: %s\n", optarg);
				return 1;
			}
			netcfg.ttl = ul;
			break;

		case 1200:
			statcfg.enabled = true;
			statcfg.address = optarg;
			break;
		case 1201:
			statcfg.enabled = true;
			statcfg.port = optarg;
			break;
		}
	}

	printf("joold is intended as a daemon, so it outputs straight to syslog.\n");
	printf("The standard streams will mostly shut up from now on.\n");
	printf("---------------------------------------------\n");

	openlog("joold", 0, LOG_DAEMON);

	error = modsocket_setup();
	if (error)
		goto end;
	error = netsocket_start();
	if (error)
		goto end;
	error = statsocket_start();
	if (error)
		goto end;

	modsocket_listen(NULL); /* Loops forever */

end:	closelog();
	fprintf(stderr, "joold error: %d\n", error);
	return error;
}
