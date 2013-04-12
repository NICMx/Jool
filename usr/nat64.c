/**
 * @file
 * Main for the NAT64's userspace application.
 * Parses parameters from the user and hands the real work to the modules inside the mode/ folder.
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


const char *argp_program_version = "NAT64 userspace app 0.1";
const char *argp_program_bug_address = "<aleiva@nic.mx>";

/**
 * The parameters received from the user, formatted and ready to be read in any order.
 */
struct arguments {
	__u16 mode;
	__u32 operation;

	// Pools
	struct in_addr pool4_addr;
	bool pool4_addr_set;

	struct ipv6_prefix pool6_prefix;
	bool pool6_prefix_set;

	// BIB, session
	bool tcp, udp, icmp;
	bool static_entries, dynamic_entries;

	struct ipv6_pair session_pair6;
	bool session_pair6_remote_set, session_pair6_local_set;
	struct ipv4_pair session_pair4;
	bool session_pair4_remote_set, session_pair4_local_set;

	// Filtering, translate
	struct filtering_config filtering;
	struct translate_config translate;
};

/**
 * The flags the user can write as program parameters.
 */
enum argp_flags {
	// Modes
	ARGP_POOL6 = '6',
	ARGP_POOL4 = '4',
	ARGP_BIB = 'b',
	ARGP_SESSION = 's',
	ARGP_FILTERING = 'y',
	ARGP_TRANSLATE = 'z',

	// Operations
	ARGP_DISPLAY = 'd',
	ARGP_ADD = 'a',
	ARGP_REMOVE = 'r',

	// Pools
	ARGP_PREFIX = 1000,
	ARGP_ADDRESS = 1001,

	// BIB, session
	ARGP_TCP = 't',
	ARGP_UDP = 'u',
	ARGP_ICMP = 'i',
//	ARGP_STATIC = 2000,
//	ARGP_DYNAMIC = 2001,
//	ARGP_IPV6 = 2010,
//	ARGP_IPV4 = 2011,
	ARGP_REMOTE6 = 2020,
	ARGP_LOCAL6 = 2021,
	ARGP_LOCAL4 = 2022,
	ARGP_REMOTE4 = 2023,

	// Filtering
	ARGP_DROP_ADDR = 3000,
	ARGP_DROP_INFO = 3001,
//	ARGP_DROP_TCP = 3002,
	ARGP_UDP_TO = 3010,
	ARGP_ICMP_TO = 3011,
	ARGP_TCP_TO = 3012,
	ARGP_TCP_TRANS_TO = 3013,

	// Translate
	ARGP_HEAD = 4000,
	ARGP_TAIL = 4001,
	ARGP_RESET_TCLASS = 4002,
	ARGP_RESET_TOS = 4003,
	ARGP_NEW_TOS = 4004,
	ARGP_DF = 4005,
	ARGP_BUILD_ID = 4006,
	ARGP_LOWER_MTU_FAIL = 4007,
	ARGP_PLATEAUS = 4010,
};

#define NUM_FORMAT "NUM"
#define PREFIX_FORMAT "ADDR6/NUM"
#define IPV6_TRANSPORT_FORMAT "ADDR6#NUM"
#define IPV4_TRANSPORT_FORMAT "ADDR6#NUM"
#define IPV4_ADDR_FORMAT "ADDR4"
#define BOOL_FORMAT "BOOL"
#define NUM_ARR_FORMAT "NUM[,NUM]*"


/*
 * OPTIONS. Field 1 in ARGP.
 * Order of fields: { NAME, KEY, ARG, FLAGS, DOC }.
 */
static struct argp_option options[] =
{
	{ 0, 0, 0, 0, "IPv6 Pool options:", 10},
	{ "pool6",		ARGP_POOL6,		0, 0, "The command will operate on the IPv6 pool." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the IPv6 pool as output (default)." },
	{ "add",		ARGP_ADD,		0, 0, "(Operation) Add a prefix to the pool." },
	{ "remove",		ARGP_REMOVE,	0, 0, "(Operation) Remove a prefix from the pool." },
	{ "prefix",		ARGP_PREFIX,	PREFIX_FORMAT, 0,
			"The prefix to be added or removed. Available on add and remove operations only." },

	{ 0, 0, 0, 0, "IPv4 Pool options:", 11 },
	{ "pool4",		ARGP_POOL4,		0, 0, "The command will operate on the IPv4 pool." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the IPv4 pool as output (default)." },
	{ "add",		ARGP_ADD,		0, 0, "(Operation) Add an address to the pool." },
	{ "remove",		ARGP_REMOVE,	0, 0, "(Operation) Remove an address from the pool." },
	{ "address",	ARGP_ADDRESS,	IPV4_ADDR_FORMAT, 0,
			"Address to be added or removed. Available on add and remove operations only." },

	{ 0, 0, 0, 0, "BIB options:", 20 },
	{ "bib",		ARGP_BIB, 		0, 0, "The command will operate on BIBs." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the table as output (default)." },
	{ "icmp",		ARGP_ICMP,		0, 0, "Print the ICMP BIB." },
	{ "tcp",		ARGP_TCP,		0, 0, "Print the TCP BIB." },
	{ "udp",		ARGP_UDP,		0, 0, "Print the UDP BIB." },
//	{ "static",		ARGP_STATIC,	0, 0,
//			"Filter out entries created dynamically (by incoming connections). " },
//	{ "dynamic",	ARGP_DYNAMIC,	0, 0,
//			"Filter out entries created statically (by the user). " },
//	{ "ipv4",		ARGP_IPV4,		IPV4_TRANSPORT_FORMAT, 0,
//			"Filter out entries unrelated to the following IPv4 address and/or port." },
//	{ "ipv6",		ARGP_IPV6,		IPV6_TRANSPORT_FORMAT, 0,
//			"Filter out entries unrelated to the following IPv4 address and/or port." },

	{ 0, 0, 0, 0, "Session options:", 21 },
	{ "session",	ARGP_SESSION,	0, 0, "The command will operate on the session tables." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the table as output (default)." },
	{ "add",		ARGP_ADD,		0, 0, "(Operation) Add an entry to the table." },
	{ "remove",		ARGP_REMOVE,	0, 0, "(Operation) Remove an entry from a table" },
	{ "icmp",		ARGP_ICMP,		0, 0, "Operate on the ICMP session table." },
	{ "tcp",		ARGP_TCP,		0, 0, "Operate on the TCP session table." },
	{ "udp",		ARGP_UDP,		0, 0, "Operate on the UDP session table." },
//	{ "static",		ARGP_STATIC,	0, 0,
//			"Filter out entries created dynamically (by incoming connections from IPv6 networks). "
//			"Available on display operation only." },
//	{ "dynamic",	ARGP_DYNAMIC,	0, 0,
//			"Filter out entries created statically (by the user). "
//			"Available on display operation only. " },
	{ "remote6",	ARGP_REMOTE6,	IPV6_TRANSPORT_FORMAT, 0,
			"This is the addres#port of the remote IPv6 node of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "local6",		ARGP_LOCAL6,	IPV6_TRANSPORT_FORMAT, 0,
			"This is the local IPv6 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "local4",		ARGP_LOCAL4,	IPV6_TRANSPORT_FORMAT, 0,
			"This is the local IPv4 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "remote4",	ARGP_REMOTE4,	IPV6_TRANSPORT_FORMAT, 0,
			"This is the addres#port of the remote IPv4 node of the entry to be added or removed. "
			"Available on add and remove operations only." },

	{ 0, 0, 0, 0, "'Filtering and Updating' step options:", 30 },
	{ "filtering",			ARGP_FILTERING,		0, 0,
			"Command is filtering related. Use alone to display configuration. "
			"Will be implicit if any other filtering command is entered." },
	{ DROP_BY_ADDR_OPT,		ARGP_DROP_ADDR,		BOOL_FORMAT, 0,
			"Use Address-Dependent Filtering." },
	{ DROP_ICMP6_INFO_OPT,	ARGP_DROP_INFO,		BOOL_FORMAT, 0,
			"Filter ICMPv6 Informational packets." },
//	{ DROP_EXTERNAL_TCP_OPT,ARGP_DROP_TCP,		BOOL_FORMAT, 0,
//			"Drop externally initiated TCP connections." },
	{ UDP_TIMEOUT_OPT,		ARGP_UDP_TO,		NUM_FORMAT, 0,
			"Set the timeout for new UDP sessions." },
	{ ICMP_TIMEOUT_OPT,		ARGP_ICMP_TO,		NUM_FORMAT, 0,
			"Set the timeout for new ICMP sessions." },
	{ TCP_EST_TIMEOUT_OPT,	ARGP_TCP_TO,		NUM_FORMAT, 0,
			"Set the established connection idle-timeout for new TCP sessions." },
	{ TCP_TRANS_TIMEOUT_OPT,ARGP_TCP_TRANS_TO,	NUM_FORMAT, 0,
			"Set the transitory connection idle-timeout for new TCP sessions." },

	{ 0, 0, 0, 0, "'Translate the Packet' step options:", 31 },
	{ "translate",			ARGP_TRANSLATE,		0, 0,
				"Command is translate related. Use alone to display configuration. "
				"Will be implicit if any other translate command is entered." },
	{ SKB_HEAD_ROOM_OPT,	ARGP_HEAD,			NUM_FORMAT, 0, "Packet head room." },
	{ SKB_TAIL_ROOM_OPT,	ARGP_TAIL,			NUM_FORMAT, 0, "Packet tail room." },
	{ RESET_TCLASS_OPT,		ARGP_RESET_TCLASS,	BOOL_FORMAT, 0, "Override IPv6 Traffic class." },
	{ RESET_TOS_OPT,		ARGP_RESET_TOS,		BOOL_FORMAT, 0, "Override IPv4 Type of Service." },
	{ NEW_TOS_OPT,			ARGP_NEW_TOS,		NUM_FORMAT, 0, "IPv4 Type of Service." },
	{ DF_ALWAYS_ON_OPT,		ARGP_DF,			BOOL_FORMAT, 0, "Always set Don't Fragment." },
	{ BUILD_IPV4_ID_OPT,	ARGP_BUILD_ID,		BOOL_FORMAT, 0, "Generate IPv4 ID." },
	{ LOWER_MTU_FAIL_OPT,	ARGP_LOWER_MTU_FAIL,BOOL_FORMAT, 0, "Decrease MTU failure rate." },
	{ MTU_PLATEAUS_OPT,		ARGP_PLATEAUS,		NUM_ARR_FORMAT,0, "MTU plateaus." },

	{ 0 },
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

	case ARGP_DISPLAY:
		arguments->operation = OP_DISPLAY;
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

	case ARGP_ADDRESS:
		error = str_to_addr4(arg, &arguments->pool4_addr);
		arguments->pool4_addr_set = true;
		break;
	case ARGP_PREFIX:
		error = str_to_prefix(arg, &arguments->pool6_prefix);
		arguments->pool6_prefix_set = true;
		break;
//	case ARGP_STATIC:
//		arguments->static_entries = true;
//		break;
//	case ARGP_DYNAMIC:
//		arguments->dynamic_entries = true;
//		break;
//
//	case ARGP_IPV6:
//		error = str_to_addr6_port(arg, &arguments->bib_addr6);
//		arguments->bib_addr6_set = true;
//		break;
//	case ARGP_IPV4:
//		error = str_to_addr4_port(arg, &arguments->bib_addr4);
//		arguments->bib_addr4_set = true;
//		break;
	case ARGP_REMOTE6:
		error = str_to_addr6_port(arg, &arguments->session_pair6.remote);
		arguments->session_pair6_remote_set = true;
		break;
	case ARGP_LOCAL6:
		error = str_to_addr6_port(arg, &arguments->session_pair6.local);
		arguments->session_pair6_local_set = true;
		break;
	case ARGP_LOCAL4:
		error = str_to_addr4_port(arg, &arguments->session_pair4.local);
		arguments->session_pair4_local_set = true;
		break;
	case ARGP_REMOTE4:
		error = str_to_addr4_port(arg, &arguments->session_pair4.remote);
		arguments->session_pair4_remote_set = true;
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
//	case ARGP_DROP_TCP:
//		arguments->mode = MODE_FILTERING;
//		arguments->operation |= DROP_EXTERNAL_TCP_MASK;
//		error = str_to_bool(arg, &arguments->filtering.drop_external_tcp);
//		break;
	case ARGP_UDP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= UDP_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, UDP_MIN, 0xFFFF);
		arguments->filtering.to.udp = temp;
		break;
	case ARGP_ICMP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= ICMP_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, 0, 0xFFFF);
		arguments->filtering.to.icmp = temp;
		break;
	case ARGP_TCP_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= TCP_EST_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, TCP_EST, 0xFFFF);
		arguments->filtering.to.tcp_est = temp;
		break;
	case ARGP_TCP_TRANS_TO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= TCP_TRANS_TIMEOUT_MASK;
		error = str_to_u16(arg, &temp, TCP_TRANS, 0xFFFF);
		arguments->filtering.to.tcp_trans = temp;
		break;

	case ARGP_HEAD:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= SKB_HEAD_ROOM_MASK;
		error = str_to_u16(arg, &arguments->translate.skb_head_room, 0, 0xFFFF);
		break;
	case ARGP_TAIL:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= SKB_TAIL_ROOM_MASK;
		error = str_to_u16(arg, &arguments->translate.skb_tail_room, 0, 0xFFFF);
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
static char doc[] = "nat64 -- The NAT64 kernel module's configuration interface.\v";


/**
 * Uses argp.h to read the parameters from the user, validates them, and returns the result as a
 * structure.
 */
int parse_args(int argc, char **argv, struct arguments *result)
{
	int error;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(result, 0, sizeof(*result));

	error = argp_parse(&argp, argc, argv, 0, 0, result);
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
int main(int argc, char **argv)
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

	case MODE_BIB:
		switch (args.operation) {
		case OP_DISPLAY:
			return bib_display(args.tcp, args.udp, args.icmp);
		default:
			log_err(ERR_UNKNOWN_OP, "Unknown operation for BIB mode: %u.", args.operation);
			return -EINVAL;
		}
		break;

	case MODE_SESSION:
		switch (args.operation) {
		case OP_DISPLAY:
			return session_display(args.tcp, args.udp, args.icmp);

		case OP_ADD:
			error = 0;
			if (!args.session_pair6_remote_set) {
				log_err(ERR_MISSING_PARAM, "Missing remote IPv6 address#port (--remote6).");
				error = -EINVAL;
			}
			if (!args.session_pair6_local_set) {
				log_err(ERR_MISSING_PARAM, "Missing local IPv6 address#port (--local6).");
				error = -EINVAL;
			}
			if (!args.session_pair4_local_set) {
				log_err(ERR_MISSING_PARAM, "Missing local IPv4 address#port (--local4).");
				error = -EINVAL;
			}
			if (!args.session_pair4_remote_set) {
				log_err(ERR_MISSING_PARAM, "Missing remote IPv4 address#port (--remote4).");
				error = -EINVAL;
			}
			if (error)
				return error;

			return session_add(args.tcp, args.udp, args.icmp, &args.session_pair6,
					&args.session_pair4);

		case OP_REMOVE:
			if (args.session_pair6_remote_set && args.session_pair6_local_set)
				return session_remove_ipv6(args.tcp, args.udp, args.icmp, &args.session_pair6);

			if (args.session_pair4_remote_set && args.session_pair4_local_set)
				return session_remove_ipv4(args.tcp, args.udp, args.icmp, &args.session_pair4);

			log_err(ERR_MISSING_PARAM, "You need to provide both the local and remote nodes' "
					"address#port, either from the IPv6 or the IPv4 side.");
			return -EINVAL;

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

	default:
		log_err(ERR_EMPTY_COMMAND, "Command seems empty; --help or --usage for info.");
		return -EINVAL;
	}
}
