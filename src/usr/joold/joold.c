#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

	/* Modsocket */

	{
		.name = "mod",
		.has_arg = required_argument,
		.val = 'm',
	}, {
		.name = "instance",
		.has_arg = required_argument,
		.val = 'i',
	},

	/* Netsocket */

	{
		.name = "net",
		.has_arg = required_argument,
		.val = 'n',
	}, {
		.name = "net.mcast.address",
		.has_arg = required_argument,
		.val = 1100,
	}, {
		.name = "net.mcast.port",
		.has_arg = required_argument,
		.val = 1101,
	}, {
		.name = "net.dev.in",
		.has_arg = required_argument,
		.val = 1102,
	}, {
		.name = "net.dev.out",
		.has_arg = required_argument,
		.val = 1103,
	}, {
		.name = "net.ttl",
		.has_arg = required_argument,
		.val = 1104,
	},

	/* Statsocket */

	{
		.name = "stats",
		.has_arg = required_argument,
		.val = 's',
	}, {
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
	printf("-V --version              Print program version number\n");
	printf("-h --help                 Print this\n");
	printf("\n");
	printf("-m --mod=FILE             Path to file containing kernel socket config\n");
	printf("-i --instance=INAME       Kernelspace Jool instance name (Default: \"default\")\n");
	printf("\n");
	printf("-n --net=FILE             Path to file containing network socket config\n");
	printf("   --net.mcast.addr=ADDR  Address where the sessions will be advertised\n");
	printf("   --net.mcast.port=STR   UDP port where the sessions will be advertised\n");
	printf("   --net.dev.in=STR       IPv4: IP_ADD_MEMBERSHIP; IPv6: IPV6_ADD_MEMBERSHIP\n");
	printf("                          (see ip(7))\n");
	printf("   --net.dev.out=STR      IPv4: IP_MULTICAST_IF, IPv6: IPV6_MULTICAST_IF\n");
	printf("                          (see ip(7))\n");
	printf("   --net.ttl=INT          Multicast datagram Time To Live\n");
	printf("\n");
	printf("-s --stats=FILE           Path to file containing stats socket config\n");
	printf("   --stats.addr=ADDR      Address to bind the stats socket to\n");
	printf("   --stats.port=STR       Port to bind the stats socket to\n");
}

int main(int argc, char **argv)
{
	char const *OPTS = "Vhm:n:s:i:";
	int opt;
	unsigned long ul;
	int error;

	modcfg.iname = "default";
	netcfg.ttl = 1;
	statcfg.address = "::";

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
				fprintf(stderr, "ttl out of range: %s\n", optarg);
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

	printf("Config:\n");
	printf("  mod.instance: %s\n", modcfg.iname);
	if (netcfg.enabled) {
		printf("  net.mcast.addr: %s\n", netcfg.mcast_addr);
		printf("  net.mcast.port: %s\n", netcfg.mcast_port);
		printf("  net.dev.in: %s\n", netcfg.in_interface);
		printf("  net.dev.out: %s\n", netcfg.out_interface);
		printf("  net.ttl: %d\n", netcfg.ttl);
	}
	if (statcfg.enabled) {
		printf("  stats.addr: %s\n", statcfg.address);
		printf("  stats.port: %s\n", statcfg.port);
	}

	printf("\n");
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
