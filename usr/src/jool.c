/**
 * @file
 * Main for the NAT64's userspace application.
 * Parses parameters from the user and hands the real work to the other .c's.
 *
 * @author Miguel González
 * @author Alberto Leiva  <-- maintenance
 */

#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/pool6.h"
#include "nat64/usr/pool4.h"
#include "nat64/usr/bib.h"
#include "nat64/usr/session.h"
#include "nat64/usr/filtering.h"
#include "nat64/usr/translate.h"
#include "nat64/usr/fragmentation.h"


const char *argp_program_version = "3.1.3";
const char *argp_program_bug_address = "jool@nic.mx";

/**
 * The parameters received from the user, formatted and ready to be read in any order.
 */
struct arguments {
	__u16 mode;
	__u32 operation;

	/* Pools */
	struct in_addr pool4_addr;
	bool pool4_addr_set;

	struct ipv6_prefix pool6_prefix;
	bool pool6_prefix_set;

	/* BIB, session */
	bool tcp, udp, icmp;
	bool static_entries, dynamic_entries;

	struct ipv6_tuple_address bib6;
	bool bib6_set;
	struct ipv4_tuple_address bib4;
	bool bib4_set;

	/* Filtering, translate, fragmentation */
	struct filtering_config filtering;
	struct translate_config translate;
	struct fragmentation_config fragmentation;
};

/**
 * configuration for showing session
 */
struct session_config session_config;

/**
 * The flags the user can write as program parameters.
 */
enum argp_flags {
	/* Modes */
	ARGP_POOL6 = '6',
	ARGP_POOL4 = '4',
	ARGP_BIB = 'b',
	ARGP_SESSION = 's',
	ARGP_FILTERING = 'y',
	ARGP_TRANSLATE = 'z',
	ARGP_FRAGMENTATION = 'f',

	/* Operations */
	ARGP_DISPLAY = 'd',
	ARGP_COUNT = 'c',
	ARGP_ADD = 'a',
	ARGP_REMOVE = 'r',

	/* Pools */
	ARGP_PREFIX = 1000,
	ARGP_ADDRESS = 1001,

	/* BIB, session */
	ARGP_TCP = 't',
	ARGP_UDP = 'u',
	ARGP_ICMP = 'i',
	ARGP_NUMERIC_HOSTNAME = 'n',
	/*
	ARGP_STATIC = 2000,
	ARGP_DYNAMIC = 2001,
	ARGP_IPV6 = 2010,
	ARGP_IPV4 = 2011,
	*/
	ARGP_BIB_IPV6 = 2020,
	ARGP_BIB_IPV4 = 2021,

	/* Filtering */
	ARGP_DROP_ADDR = 3000,
	ARGP_DROP_INFO = 3001,
	ARGP_DROP_TCP = 3002,
	ARGP_UDP_TO = 3010,
	ARGP_ICMP_TO = 3011,
	ARGP_TCP_TO = 3012,
	ARGP_TCP_TRANS_TO = 3013,

	/* Translate */
	ARGP_RESET_TCLASS = 4002,
	ARGP_RESET_TOS = 4003,
	ARGP_NEW_TOS = 4004,
	ARGP_DF = 4005,
	ARGP_BUILD_ID = 4006,
	ARGP_LOWER_MTU_FAIL = 4007,
	ARGP_PLATEAUS = 4010,
	ARGP_MIN_IPV6_MTU = 4011,

	/* Fragmentation */
	ARGP_FRAG_TO = 5000,
};

#define NUM_FORMAT "NUM"
#define PREFIX_FORMAT "ADDR6/NUM"
#define IPV6_TRANSPORT_FORMAT "ADDR6#NUM"
#define IPV4_TRANSPORT_FORMAT "ADDR4#NUM"
#define IPV4_ADDR_FORMAT "ADDR4"
#define BOOL_FORMAT "BOOL"
#define NUM_ARR_FORMAT "NUM[,NUM]*"


/*
 * OPTIONS. Field 1 in ARGP.
 * Order of fields: { NAME, KEY, ARG, FLAGS, DOC }.
 */
static struct argp_option options[] =
{
	{ NULL, 0, NULL, 0, "IPv6 Pool options:", 10},
	{ "pool6",		ARGP_POOL6,		NULL, 0, "The command will operate on the IPv6 pool." },
	{ "display",	ARGP_DISPLAY,	NULL, 0, "(Operation) Print the IPv6 pool as output (default)." },
	{ "count",		ARGP_COUNT,		NULL, 0, "(Operation) Print the number of IPv6 prefixes registered." },
	{ "add",		ARGP_ADD,		NULL, 0, "(Operation) Add a prefix to the pool." },
	{ "remove",		ARGP_REMOVE,	NULL, 0, "(Operation) Remove a prefix from the pool." },
	{ "prefix",		ARGP_PREFIX,	PREFIX_FORMAT, 0,
			"The prefix to be added or removed. Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "IPv4 Pool options:", 11 },
	{ "pool4",		ARGP_POOL4,		NULL, 0, "The command will operate on the IPv4 pool." },
	{ "display",	ARGP_DISPLAY,	NULL, 0, "(Operation) Print the IPv4 pool as output (default)." },
	{ "count",		ARGP_COUNT,		NULL, 0, "(Operation) Print the number of IPv4 addresses registered." },
	{ "add",		ARGP_ADD,		NULL, 0, "(Operation) Add an address to the pool." },
	{ "remove",		ARGP_REMOVE,	NULL, 0, "(Operation) Remove an address from the pool." },
	{ "address",	ARGP_ADDRESS,	IPV4_ADDR_FORMAT, 0,
			"Address to be added or removed. Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "BIB options:", 20 },
	{ "bib",		ARGP_BIB, 		NULL, 0, "The command will operate on BIBs." },
	{ "display",	ARGP_DISPLAY,	NULL, 0, "(Operation) Print the table as output (default)." },
	{ "count",		ARGP_COUNT,		NULL, 0, "(Operation) Print the number of BIB entries registered." },
	{ "add",		ARGP_ADD,		NULL, 0, "(Operation) Add an entry to the table." },
	{ "remove",		ARGP_REMOVE,	NULL, 0, "(Operation) Remove an entry from a table" },
	{ "icmp",		ARGP_ICMP,		NULL, 0, "Print the ICMP BIB." },
	{ "tcp",		ARGP_TCP,		NULL, 0, "Print the TCP BIB." },
	{ "udp",		ARGP_UDP,		NULL, 0, "Print the UDP BIB." },
	/*
	{ "static",		ARGP_STATIC,	NULL, 0,
			"Filter out entries created dynamically (by incoming connections). " },
	{ "dynamic",	ARGP_DYNAMIC,	NULL, 0,
			"Filter out entries created statically (by the user). " },
	{ "ipv4",		ARGP_IPV4,		IPV4_TRANSPORT_FORMAT, 0,
			"Filter out entries unrelated to the following IPv4 address and/or port." },
	{ "ipv6",		ARGP_IPV6,		IPV6_TRANSPORT_FORMAT, 0,
			"Filter out entries unrelated to the following IPv4 address and/or port." },
	*/
	{ "bib6",		ARGP_BIB_IPV6,	IPV6_TRANSPORT_FORMAT, 0,
			"This is the addres#port of the remote IPv6 node of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "bib4",		ARGP_BIB_IPV4,	IPV4_TRANSPORT_FORMAT, 0,
			"This is the local IPv4 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "Session options:", 21 },
	{ "session",	ARGP_SESSION,	NULL, 0, "The command will operate on the session tables." },
	{ "display",	ARGP_DISPLAY,	NULL, 0, "(Operation) Print the table as output (default)." },
	{ "count",		ARGP_COUNT,		NULL, 0, "(Operation) Print the number of session entries registered." },
	{ "icmp",		ARGP_ICMP,		NULL, 0, "Operate on the ICMP session table." },
	{ "tcp",		ARGP_TCP,		NULL, 0, "Operate on the TCP session table." },
	{ "udp",		ARGP_UDP,		NULL, 0, "Operate on the UDP session table." },
	{ "numeric",		ARGP_NUMERIC_HOSTNAME,	NULL, 0, "don't resolve names." },
	/*
	{ "static",		ARGP_STATIC,	NULL, 0,
			"Filter out entries created dynamically (by incoming connections from IPv6 networks). "
			"Available on display operation only." },
	{ "dynamic",	ARGP_DYNAMIC,	NULL, 0,
			"Filter out entries created statically (by the user). "
			"Available on display operation only. " },
	 */

	{ NULL, 0, NULL, 0, "'Filtering and Updating' step options:", 30 },
	{ "filtering",			ARGP_FILTERING,		NULL, 0,
			"Command is filtering related. Use alone to display configuration. "
			"Will be implicit if any other filtering command is entered." },
	{ DROP_BY_ADDR_OPT,		ARGP_DROP_ADDR,		BOOL_FORMAT, 0,
			"Use Address-Dependent Filtering." },
	{ DROP_ICMP6_INFO_OPT,	ARGP_DROP_INFO,		BOOL_FORMAT, 0,
			"Filter ICMPv6 Informational packets." },
	{ DROP_EXTERNAL_TCP_OPT,ARGP_DROP_TCP,		BOOL_FORMAT, 0,
			"Drop externally initiated TCP connections." },
	{ UDP_TIMEOUT_OPT,		ARGP_UDP_TO,		NUM_FORMAT, 0,
			"Set the timeout for new UDP sessions." },
	{ ICMP_TIMEOUT_OPT,		ARGP_ICMP_TO,		NUM_FORMAT, 0,
			"Set the timeout for new ICMP sessions." },
	{ TCP_EST_TIMEOUT_OPT,	ARGP_TCP_TO,		NUM_FORMAT, 0,
			"Set the established connection idle-timeout for new TCP sessions." },
	{ TCP_TRANS_TIMEOUT_OPT,ARGP_TCP_TRANS_TO,	NUM_FORMAT, 0,
			"Set the transitory connection idle-timeout for new TCP sessions." },

	{ NULL, 0, NULL, 0, "'Translate the Packet' step options:", 31 },
	{ "translate",			ARGP_TRANSLATE,		NULL, 0,
				"Command is translate related. Use alone to display configuration. "
				"Will be implicit if any other translate command is entered." },
	{ RESET_TCLASS_OPT,		ARGP_RESET_TCLASS,	BOOL_FORMAT, 0, "Override IPv6 Traffic class." },
	{ RESET_TOS_OPT,		ARGP_RESET_TOS,		BOOL_FORMAT, 0, "Override IPv4 Type of Service." },
	{ NEW_TOS_OPT,			ARGP_NEW_TOS,		NUM_FORMAT, 0, "IPv4 Type of Service." },
	{ DF_ALWAYS_ON_OPT,		ARGP_DF,			BOOL_FORMAT, 0, "Always set Don't Fragment." },
	{ BUILD_IPV4_ID_OPT,	ARGP_BUILD_ID,		BOOL_FORMAT, 0, "Generate IPv4 ID." },
	{ LOWER_MTU_FAIL_OPT,	ARGP_LOWER_MTU_FAIL,BOOL_FORMAT, 0, "Decrease MTU failure rate." },
	{ MTU_PLATEAUS_OPT,		ARGP_PLATEAUS,		NUM_ARR_FORMAT,0, "MTU plateaus." },
	{ MIN_IPV6_MTU_OPT,		ARGP_MIN_IPV6_MTU,	NUM_FORMAT, 0, "Minimum IPv6 MTU." },

	{ NULL, 0, NULL, 0, "'Fragmentation' options:", 40 },
	{ "fragmentation",			ARGP_FRAGMENTATION,		NULL, 0,
			"Command is fragmentation related. Use alone to display configuration. "
			"Will be implicit if any other fragmentation command is entered." },
	{ FRAGMENTATION_TIMEOUT_OPT,		ARGP_FRAG_TO,		NUM_FORMAT, 0,
			"Set the timeout for arrival of fragments." },

	{ NULL },
};

/*
 * PARSER. Field 2 in ARGP.
 */
static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	int error = 0;
	__u16 temp;

	switch (key) {
	case ARGP_POOL6:
		arguments->mode = MODE_POOL6;
		break;
	case ARGP_POOL4:
		arguments->mode = MODE_POOL4;
		break;
	case ARGP_BIB:
		arguments->mode = MODE_BIB;
		break;
	case ARGP_SESSION:
		arguments->mode = MODE_SESSION;
		break;
	case ARGP_FILTERING:
		arguments->mode = MODE_FILTERING;
		break;
	case ARGP_TRANSLATE:
		arguments->mode = MODE_TRANSLATE;
		break;
	case ARGP_FRAGMENTATION:
		arguments->mode = MODE_FRAGMENTATION;
		break;

	case ARGP_DISPLAY:
		arguments->operation = OP_DISPLAY;
		break;
	case ARGP_COUNT:
		arguments->operation = OP_COUNT;
		break;
	case ARGP_ADD:
		arguments->operation = OP_ADD;
		break;
	case ARGP_REMOVE:
		arguments->operation = OP_REMOVE;
		break;

	case ARGP_UDP:
		arguments->udp = true;
		break;
	case ARGP_TCP:
		arguments->tcp = true;
		break;
	case ARGP_ICMP:
		arguments->icmp = true;
		break;
	case ARGP_NUMERIC_HOSTNAME:
		session_config.numeric_hostname = true;
		break;

	case ARGP_ADDRESS:
		error = str_to_addr4(arg, &arguments->pool4_addr);
		arguments->pool4_addr_set = true;
		break;
	case ARGP_PREFIX:
		error = str_to_prefix(arg, &arguments->pool6_prefix);
		arguments->pool6_prefix_set = true;
		break;
	/*
	case ARGP_STATIC:
		arguments->static_entries = true;
		break;
	case ARGP_DYNAMIC:
		arguments->dynamic_entries = true;
		break;
	*/

	case ARGP_BIB_IPV6:
		error = str_to_addr6_port(arg, &arguments->bib6);
		arguments->bib6_set = true;
		break;
	case ARGP_BIB_IPV4:
		error = str_to_addr4_port(arg, &arguments->bib4);
		arguments->bib4_set = true;
		break;

	case ARGP_DROP_ADDR:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= DROP_BY_ADDR_MASK;
		error = str_to_bool(arg, &arguments->filtering.drop_by_addr);
		break;
	case ARGP_DROP_INFO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= DROP_ICMP6_INFO_MASK;
		error = str_to_bool(arg, &arguments->filtering.drop_icmp6_info);
		break;
	case ARGP_DROP_TCP:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= DROP_EXTERNAL_TCP_MASK;
		error = str_to_bool(arg, &arguments->filtering.drop_external_tcp);
		break;
	case ARGP_UDP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= UDP_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, UDP_MIN, 0xFFFF);
		arguments->filtering.to.udp = temp * 1000;
		break;
	case ARGP_ICMP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= ICMP_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->filtering.to.icmp = temp * 1000;
		break;
	case ARGP_TCP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= TCP_EST_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, TCP_EST, 0xFFFF);
		arguments->filtering.to.tcp_est = temp * 1000;
		break;
	case ARGP_TCP_TRANS_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= TCP_TRANS_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, TCP_TRANS, 0xFFFF);
		arguments->filtering.to.tcp_trans = temp * 1000;
		break;

	case ARGP_RESET_TCLASS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= RESET_TCLASS_MASK;
		error = str_to_bool(arg, &arguments->translate.reset_traffic_class);
		break;
	case ARGP_RESET_TOS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= RESET_TOS_MASK;
		error = str_to_bool(arg, &arguments->translate.reset_tos);
		break;
	case ARGP_NEW_TOS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= NEW_TOS_MASK;
		error = str_to_u8(arg, &arguments->translate.new_tos, 0, 0xFF);
		break;
	case ARGP_DF:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= DF_ALWAYS_ON_MASK;
		error = str_to_bool(arg, &arguments->translate.df_always_on);
		break;
	case ARGP_BUILD_ID:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= BUILD_IPV4_ID_MASK;
		error = str_to_bool(arg, &arguments->translate.build_ipv4_id);
		break;
	case ARGP_LOWER_MTU_FAIL:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= LOWER_MTU_FAIL_MASK;
		error = str_to_bool(arg, &arguments->translate.lower_mtu_fail);
		break;
	case ARGP_PLATEAUS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= MTU_PLATEAUS_MASK;
		error = str_to_u16_array(arg, &arguments->translate.mtu_plateaus,
				&arguments->translate.mtu_plateau_count);
		break;
	case ARGP_MIN_IPV6_MTU:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= MIN_IPV6_MTU_MASK;
		error = str_to_u16(arg, &arguments->translate.min_ipv6_mtu, 1280, 65535);
		break;

	case ARGP_FRAG_TO:
		arguments->mode = MODE_FRAGMENTATION;
		arguments->operation |= FRAGMENT_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, FRAGMENT_MIN, 0xFFFF);
		arguments->fragmentation.fragment_timeout = temp * 1000;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return error;
}

/*
 * ARGS_DOC. Field 3 in ARGP.
 * A description of the non-option command-line arguments we accept.
 */
static char args_doc[] = "";

/*
 * DOC. Field 4 in ARGP.
 * Program documentation.
 */
static char doc[] = "jool -- The Jool kernel module's configuration interface.\v";


/**
 * Uses argp.h to read the parameters from the user, validates them, and returns the result as a
 * structure.
 */
static int parse_args(int argc, char **argv, struct arguments *result)
{
	int error;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(result, 0, sizeof(*result));

	error = argp_parse(&argp, argc, argv, 0, NULL, result);
	if (error != 0)
		return error;

	if (!result->tcp && !result->udp && !result->icmp) {
		result->tcp = true;
		result->udp = true;
		result->icmp = true;
	}

	if (!result->static_entries && !result->dynamic_entries) {
		result->static_entries = true;
		result->dynamic_entries = true;
	}

	return 0;
}

/*
 * The main function.
 */
static int main_wrapped(int argc, char **argv)
{
	struct arguments args;
	int error;

	error = parse_args(argc, argv, &args);
	if (error)
		return error;

	switch (args.mode) {
	case MODE_POOL6:
		switch (args.operation) {
		case OP_DISPLAY:
			return pool6_display();
		case OP_COUNT:
			return pool6_count();
		case OP_ADD:
			if (!args.pool6_prefix_set) {
				log_err(ERR_MISSING_PARAM, "Please enter the prefix to be added (--prefix).");
				return -EINVAL;
			}
			return pool6_add(&args.pool6_prefix);
		case OP_REMOVE:
			if (!args.pool6_prefix_set) {
				log_err(ERR_MISSING_PARAM, "Please enter the prefix to be removed (--prefix).");
				return -EINVAL;
			}
			return pool6_remove(&args.pool6_prefix);
		default:
			log_err(ERR_UNKNOWN_OP, "Unknown operation for IPv6 pool mode: %u.", args.operation);
			return -EINVAL;
		}
		break;

	case MODE_POOL4:
		switch (args.operation) {
		case OP_DISPLAY:
			return pool4_display();
		case OP_COUNT:
			return pool4_count();
		case OP_ADD:
			if (!args.pool4_addr_set) {
				log_err(ERR_MISSING_PARAM, "Please enter the address to be added (--address).");
				return -EINVAL;
			}
			return pool4_add(&args.pool4_addr);
		case OP_REMOVE:
			if (!args.pool4_addr_set) {
				log_err(ERR_MISSING_PARAM, "Please enter the address to be removed (--address).");
				return -EINVAL;
			}
			return pool4_remove(&args.pool4_addr);
		default:
			log_err(ERR_UNKNOWN_OP, "Unknown operation for IPv4 pool mode: %u.", args.operation);
			return -EINVAL;
		}
		break;

	case MODE_BIB:
		switch (args.operation) {
		case OP_DISPLAY:
			return bib_display(args.tcp, args.udp, args.icmp);
		case OP_COUNT:
			return bib_count(args.tcp, args.udp, args.icmp);

		case OP_ADD:
			error = 0;
			if (!args.bib6_set) {
				log_err(ERR_MISSING_PARAM, "Missing IPv6 address#port (--bib6).");
				error = -EINVAL;
			}
			if (!args.bib4_set) {
				log_err(ERR_MISSING_PARAM, "Missing IPv4 address#port (--bib4).");
				error = -EINVAL;
			}
			if (error)
				return error;

			return bib_add(args.tcp, args.udp, args.icmp, &args.bib6, &args.bib4);

		case OP_REMOVE:
			if (args.bib6_set)
				return bib_remove_ipv6(args.tcp, args.udp, args.icmp, &args.bib6);
			else if (args.bib4_set)
				return bib_remove_ipv4(args.tcp, args.udp, args.icmp, &args.bib4);

			log_err(ERR_MISSING_PARAM, "I need either the IPv4 transport address or the IPv6 "
					"transport address of the entry you want to remove.");
			return -EINVAL;

		default:
			log_err(ERR_UNKNOWN_OP, "Unknown operation for session mode: %u.", args.operation);
			return -EINVAL;
		}
		break;

	case MODE_SESSION:
		switch (args.operation) {
		case OP_DISPLAY:
			return session_display(args.tcp, args.udp, args.icmp);
		case OP_COUNT:
			return session_count(args.tcp, args.udp, args.icmp);
		default:
			log_err(ERR_UNKNOWN_OP, "Unknown operation for session mode: %u.", args.operation);
			return -EINVAL;
		}
		break;

	case MODE_FILTERING:
		return filtering_request(args.operation, &args.filtering);

	case MODE_TRANSLATE:
		error = translate_request(args.operation, &args.translate);
		if (args.translate.mtu_plateaus)
			free(args.translate.mtu_plateaus);
		return error;

	case MODE_FRAGMENTATION:
		return fragmentation_request(args.operation, &args.fragmentation);

	default:
		log_err(ERR_EMPTY_COMMAND, "Command seems empty; --help or --usage for info.");
		return -EINVAL;
	}
}

int main(int argc, char **argv)
{
	return -main_wrapped(argc, argv);
}
