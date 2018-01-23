#include "options.h"

#include <argp.h>
#include <stdlib.h>
#include <string.h>

static struct argp_option options[] = {
	{
		.doc = "Configuration targets/modes:",
		.group = 2,
	}, {
		.name = OPTNAME_GLOBAL,
		.key = ARGP_GLOBAL,
		.doc = "The command will operate on miscellaneous configuration values (default).",
	}, {
		.name = OPTNAME_POOL4,
		.key = ARGP_POOL4,
		.doc = "The command will operate on the IPv4 transport address pool.",
	}, {
		.name = OPTNAME_EAMT,
		.key = ARGP_EAMT,
		.doc = "The command will operate on the EAM table.",
	}, {
		.name = OPTNAME_BIB,
		.key = ARGP_BIB,
		.doc = "The command will operate on the BIBs.",
	}, {
		.name = OPTNAME_SESSION,
		.key = ARGP_SESSION,
		.doc = "The command will operate on the session tables.",
	}, {
		.name = "file",
		.key = ARGP_PARSE_FILE,
		.arg = "STRING",
		.doc = "Read the configuration from a JSON file.",
	}, {
		.name = OPTNAME_JOOLD,
		.key = ARGP_JOOLD,
		.doc = "The command will control the kernel half of joold.",
	}, {
		.name = OPTNAME_INSTANCE,
		.key = ARGP_INSTANCE,
		.doc = "The command will operate on per-namespace Jool instances.",
	},

	{
		.doc = "Operations:",
		.group = 3,
	}, {
		.name = OPTNAME_DISPLAY,
		.key = ARGP_DISPLAY,
		.doc = "Print the target (default).",
	}, {
		.name = OPTNAME_ADD,
		.key = ARGP_ADD,
		.doc = "Add an element to the target.",
	}, {
		.name = OPTNAME_UPDATE,
		.key = ARGP_UPDATE,
		.doc = "Change something in the target.",
	}, {
		.name = OPTNAME_REMOVE,
		.key = ARGP_REMOVE,
		.doc = "Remove an element from the target.",
	}, {
		.name = OPTNAME_FLUSH,
		.key = ARGP_FLUSH,
		.doc = "Clear the target.",
	}, {
		.name = OPTNAME_ADVERTISE,
		.key = ARGP_ADVERTISE,
		.doc = "Advertise the entire session DB to the multicast group.",
	},{
		.name = OPTNAME_TEST,
		.key = ARGP_TEST,
		.doc = ":>",
	},

	{
		.doc = "Database miscellaneous options:",
		.group = 4,
	}, {
		.name = "csv",
		.key = ARGP_CSV,
		.doc = "Print in CSV format. Available on display operation only.",
	}, {
		.name = "no-headers",
		.key = ARGP_NO_HEADERS,
		.doc = "Do not print table headers.",
	}, {
		.name = "quick",
		.key = ARGP_QUICK,
		.doc = "Do not clean the BIB and/or session tables after removing. Available on remove and flush operations only.",
	}, {
		.name = OPTNAME_MARK,
		.key = ARGP_MARK,
		.arg = NUM_FORMAT,
		.doc = "Only packets carrying this mark will match this pool4 entry. Available on add and remove operations only.",
	}, {
		.name = OPTNAME_MAX_ITERATIONS,
		.key = ARGP_MAX_ITERATIONS,
		.arg = NUM_FORMAT,
		.doc = "Max Iterations (column) value of the entry being added or updated.",
	}, {
		.name = "force",
		.key = ARGP_FORCE,
		.doc = "Ignore warnings.",
	}, {
		.name = "icmp",
		.key = ARGP_ICMP,
		.doc = "Operate on the ICMP table.",
	}, {
		.name = "tcp",
		.key = ARGP_TCP,
		.doc = "Operate on the TCP table.",
	}, {
		.name = "udp",
		.key = ARGP_UDP,
		.doc = "Operate on the UDP table.",
	}, {
		.name = "numeric",
		.key = ARGP_NUMERIC_HOSTNAME,
		.doc = "Don't resolve names. Available on display operation only.",
	},

	/*
	 * Note: Global options must be at the end because of
	 * get_global_options().
	 */
	{
#define GLOBAL_OPTS_HEADER "'Global' options:"
		.doc = GLOBAL_OPTS_HEADER,
		.group = 6,
	}, {
		.name = OPTNAME_ZEROIZE_TC,
		.key = ARGP_RESET_TCLASS,
		.arg = BOOL_FORMAT,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
	}, {
		.name = OPTNAME_OVERRIDE_TOS,
		.key = ARGP_RESET_TOS,
		.arg = BOOL_FORMAT,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
	}, {
		.name = OPTNAME_TOS,
		.key = ARGP_NEW_TOS,
		.arg = NUM_FORMAT,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
	}, {
		.name = OPTNAME_MTU_PLATEAUS,
		.key = ARGP_PLATEAUS,
		.arg = NUM_ARRAY_FORMAT,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
	}, {
		.name = OPTNAME_DROP_BY_ADDR,
		.key = ARGP_DROP_ADDR,
		.arg = BOOL_FORMAT,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
	}, {
		.name = OPTNAME_DROP_ICMP6_INFO,
		.key = ARGP_DROP_INFO,
		.arg = BOOL_FORMAT,
		.doc = "Filter ICMPv6 Informational packets?\n",
	}, {
		.name = OPTNAME_DROP_EXTERNAL_TCP,
		.key = ARGP_DROP_TCP,
		.arg = BOOL_FORMAT,
		.doc = "Drop externally initiated TCP connections?\n",
	}, {
		.name = OPTNAME_UDP_TIMEOUT,
		.key = ARGP_UDP_TO,
		.arg = NUM_FORMAT,
		.doc = "Set the UDP session lifetime (in seconds).\n",
	}, {
		.name = OPTNAME_ICMP_TIMEOUT,
		.key = ARGP_ICMP_TO,
		.arg = NUM_FORMAT,
		.doc = "Set the timeout for ICMP sessions.\n",
	}, {
		.name = OPTNAME_TCPEST_TIMEOUT,
		.key = ARGP_TCP_TO,
		.arg = NUM_FORMAT,
		.doc = "Set the TCP established session lifetime (in seconds).\n",
	}, {
		.name = OPTNAME_TCPTRANS_TIMEOUT,
		.key = ARGP_TCP_TRANS_TO,
		.arg = NUM_FORMAT,
		.doc = "Set the TCP transitory session lifetime (in seconds).\n",
	}, {
		.name = OPTNAME_MAX_SO,
		.key = ARGP_STORED_PKTS,
		.arg = NUM_FORMAT,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.\n",
	}, {
		.name = OPTNAME_SRC_ICMP6E_BETTER,
		.key = ARGP_SRC_ICMP6ERRS_BETTER,
		.arg = BOOL_FORMAT,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?\n",
	}, {
		.name = OPTNAME_F_ARGS,
		.key = ARGP_F_ARGS,
		.arg = NUM_FORMAT,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.\n",
	}, {
		.name = OPTNAME_HANDLE_FIN_RCV_RST,
		.key = ARGP_HANDLE_RST_DURING_FIN_RCV,
		.arg = BOOL_FORMAT,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
	}, {
		.name = OPTNAME_BIB_LOGGING,
		.key = ARGP_BIB_LOGGING,
		.arg = BOOL_FORMAT,
		.doc = "Log BIBs as they are created and destroyed?\n",
	}, {
		.name = OPTNAME_SESSION_LOGGING,
		.key = ARGP_SESSION_LOGGING,
		.arg = BOOL_FORMAT,
		.doc = "Log sessions as they are created and destroyed?\n",
	}, {
		.name = OPTNAME_AMEND_UDP_CSUM,
		.key = ARGP_COMPUTE_CSUM_ZERO,
		.arg = BOOL_FORMAT,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.\n",
	}, {
		.name = OPTNAME_EAM_HAIRPIN_MODE,
		.key = ARGP_EAM_HAIRPIN_MODE,
		.arg = NUM_FORMAT,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
	}, {
		.name = OPTNAME_RANDOMIZE_RFC6791,
		.key = ARGP_RANDOMIZE_RFC6791,
		.arg = BOOL_FORMAT,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.\n",
	}, {
		.name = OPTNAME_SS_ENABLED,
		.key = ARGP_SS_ENABLED,
		.arg = BOOL_FORMAT,
		.doc = "Enable Session Synchronization?",
	}, {
		.name = OPTNAME_SS_FLUSH_ASAP,
		.key = ARGP_SS_FLUSH_ASAP,
		.arg = BOOL_FORMAT,
		.doc = "Try to synchronize sessions as soon as possible?",
	}, {
		.name = OPTNAME_SS_FLUSH_DEADLINE,
		.key = ARGP_SS_FLUSH_DEADLINE,
		.arg = NUM_FORMAT,
		.doc = "Inactive milliseconds after which to force a session sync.",
	}, {
		.name = OPTNAME_SS_CAPACITY,
		.key = ARGP_SS_CAPACITY,
		.arg = NUM_FORMAT,
		.doc = "Maximim number of queuable entries.",
	}, {
		.name = OPTNAME_SS_MAX_PAYLOAD,
		.key = ARGP_SS_MAX_PAYLOAD,
		.arg = NUM_FORMAT,
		.doc = "Maximum amount of bytes joold should send per packet.",
	}, {
		.name = "rfc6791v6-prefix",
		.key = ARGP_RFC6791V6_PREFIX,
		.arg = OPTIONAL_PREFIX6_FORMAT,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
	},

	{ 0 },
};

struct argp_option *get_options(void)
{
	return options;
}

struct argp_option *get_global_options(void)
{
	const unsigned int OPTS_SIZE = sizeof(options) / sizeof(options[0]);
	unsigned int i;

	for (i = 0; i < OPTS_SIZE; i++)
		if (strcmp(options[i].name, GLOBAL_OPTS_HEADER) == 0)
			return &options[i + 1];

	log_err("Bug: There is no globals section.");
	return NULL;
}
