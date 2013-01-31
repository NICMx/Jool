/**
 * @file
 * Main for the NAT64's userspace application.
 * Parses parameters from the user and hands the real work to the modules inside the mode/ folder.
 *
 * @author Miguel González
 * @author Alberto Leiva  <-- maintenance
 */

#include <stdio.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>

#include "str_utils.h"
#include "mode.h"
#include "nf_nat64_config.h"
#include "xt_nat64_module_comm.h"
#include "xt_nat64_module_conf_validation.h"


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
	struct ipv6_prefix pool6_prefix;

	// BIB, session
	bool tcp, udp, icmp;
	bool static_entries, dynamic_entries;
	struct ipv6_tuple_address bib_addr6;
	struct ipv4_tuple_address bib_addr4;
	struct ipv6_pair session_pair6;
	struct ipv4_pair session_pair4;

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
	ARGP_TRANSLATE = 'y',
	ARGP_FILTERING = 'z',

	// Operations
	ARGP_DISPLAY = 'd',
	ARGP_ADD = 'a',
	ARGP_REMOVE = 'r',

	// Pools
	ARGP_PREFIX = 603,
	ARGP_ADDRESS = 601,

	// BIB, session
	ARGP_TCP = 't',
	ARGP_UDP = 'u',
	ARGP_ICMP = 'i',
	ARGP_STATIC = 669,
	ARGP_DYNAMIC = 668,
	ARGP_IPV6 = 660,
	ARGP_IPV4 = 440,
	ARGP_REMOTE6 = 666,
	ARGP_LOCAL6 = 6666,
	ARGP_LOCAL4 = 4444,
	ARGP_REMOTE4 = 444,

	// Filtering
	ARGP_ADF = 1212,
	ARGP_FINFO = 1213,
	ARGP_DROPTCP = 1214,

	// Translate
	ARGP_HEAD = 1201,
	ARGP_TAIL = 1202,
	ARGP_O6TCLASS = 1203,
	ARGP_O4TCLASS = 1204,
	ARGP_4TCLASS = 1205,
	ARGP_DF = 1206,
	ARGP_GENID = 1207,
	ARGP_IMP_MTU = 1208,
	ARGP_MIN_MTU6 = 1209,
	ARGP_MIN_MTU4 = 1210,
	ARGP_PLATEAU = 1211,
};

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
	{ "prefix",		ARGP_PREFIX,	"IP/mask", 0,
			"The prefix to be added or removed. Available on add and remove operations only." },

	{ 0, 0, 0, 0, "IPv4 Pool options:", 11 },
	{ "pool4",		ARGP_POOL4,		0, 0, "The command will operate on the IPv4 pool." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the IPv4 pool as output (default)." },
	{ "add",		ARGP_ADD,		0, 0, "(Operation) Add an address to the pool." },
	{ "remove",		ARGP_REMOVE,	0, 0, "(Operation) Remove an address from the pool." },
	{ "address",	ARGP_ADDRESS,	"IP", 0,
			"Address to be added or removed. Available on add and remove operations only." },

	{ 0, 0, 0, 0, "BIB options:", 20 },
	{ "bib",		ARGP_BIB, 		0, 0, "The command will operate on BIBs." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the table as output (default)." },
	{ "icmp",		ARGP_ICMP,		0, 0, "Print the ICMP BIB." },
	{ "tcp",		ARGP_TCP,		0, 0, "Print the TCP BIB." },
	{ "udp",		ARGP_UDP,		0, 0, "Print the UDP BIB." },
	{ "static",		ARGP_STATIC,	0, 0,
			"Filter out entries created dynamically (by incoming connections). "
			"-- TO BE IMPLEMENTED" },
	{ "dynamic",	ARGP_DYNAMIC,	0, 0,
			"Filter out entries created statically (by the user). "
			"-- TO BE IMPLEMENTED" },
	{ "ipv4",		ARGP_IPV4,		"IP#port", 0,
			"Filter out entries unrelated to the following IPv4 address and/or port." },
	{ "ipv6",		ARGP_IPV6,		"IP#port", 0,
			"Filter out entries unrelated to the following IPv4 address and/or port." },

	{ 0, 0, 0, 0, "Session options:", 21 },
	{ "session",	ARGP_SESSION,	0, 0, "The command will operate on the session tables." },
	{ "display",	ARGP_DISPLAY,	0, 0, "(Operation) Print the table as output (default)." },
	{ "add",		ARGP_ADD,		0, 0, "(Operation) Add an entry to the table." },
	{ "remove",		ARGP_REMOVE,	0, 0, "(Operation) Remove an entry from a table" },
	{ "icmp",		ARGP_ICMP,		0, 0, "Operate on the ICMP session table." },
	{ "tcp",		ARGP_TCP,		0, 0, "Operate on the TCP session table." },
	{ "udp",		ARGP_UDP,		0, 0, "Operate on the UDP session table." },
	{ "static",		ARGP_STATIC,	0, 0,
			"Filter out entries created dynamically (by incoming connections from IPv6 networks). "
			"Available on display operation only."
			"-- TO BE IMPLEMENTED" },
	{ "dynamic",	ARGP_DYNAMIC,	0, 0,
			"Filter out entries created statically (by the user). "
			"Available on display operation only. "
			"-- TO BE IMPLEMENTED" },
	{ "remote6",	ARGP_REMOTE6,	"IP#port", 0,
			"This is the addres#port of the remote IPv6 node of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "local6",		ARGP_LOCAL6,	"IP#port", 0,
			"This is the local IPv6 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "local4",		ARGP_LOCAL4,	"IP#port", 0,
			"This is the local IPv4 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "remote4",	ARGP_REMOTE4,	"IP#port", 0,
			"This is the addres#port of the remote IPv4 node of the entry to be added or removed. "
			"Available on add and remove operations only." },

	{ 0, 0, 0, 0, "'Filtering and Updating' step options:", 30 },
	{ "adf",		ARGP_ADF,		"true/false", 0, "Use Address-Dependent Filtering." },
	{ "finfo",		ARGP_FINFO,		"true/false", 0, "Filter ICMPv6 Informational packets." },
	{ "droptcp",	ARGP_DROPTCP,	"true/false", 0, "Drop externally initiated TCP connections" },
	// TODO agregar timeouts

	{ 0, 0, 0, 0, "'Translate the Packet' step options:", 31 },
	{ "head",		ARGP_HEAD,		"NUM", 0, "Packet head room." },
	{ "tail",		ARGP_TAIL,		"NUM", 0, "Packet tail room." },
	{ "o6tclass",	ARGP_O6TCLASS,	"true/false", 0, "Override IPv6 Traffic class." },
	{ "o4tclass",	ARGP_O4TCLASS,	"true/false", 0, "Override IPv4 Traffic class." },
	{ "4tclass",	ARGP_4TCLASS,	"NUM", 0, "IPv4 Traffic class." },
	{ "df",			ARGP_DF,		"true/false", 0, "Always set Don't Fragment." },
	{ "genid",		ARGP_GENID,		"true/false", 0, "Generate IPv4 ID." },
	{ "imp_mtu_rate",ARGP_IMP_MTU,	"true/false", 0, "Improve MTU failure rate." },
	{ "min_ipv6_mtu",ARGP_MIN_MTU6,	"NUM", 0, "Specifies minimal MTU value used in IPv6 network." },
	{ "min_ipv4_mtu",ARGP_MIN_MTU4,	"NUM", 0, "Specifies minimal MTU value used in IPv4 network." },
	{ "mtu_plateau",ARGP_PLATEAU,	"NUM", 0, "MTU plateaus." },

	{ 0 },
};

/*
 * PARSER. Field 2 in ARGP.
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

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
		// TODO (warning) test this terminates the parse.
		if (!str_to_addr4(arg, &arguments->pool4_addr)) {
			printf("Cannot parse '%s' as a IPv4 address.", arg);
			return RESPONSE_PARSE_FAIL;
		}
		break;
	case ARGP_PREFIX:
		if (!str_to_prefix(arg, &arguments->pool6_prefix))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_STATIC:
		arguments->static_entries = true;
		break;
	case ARGP_DYNAMIC:
		arguments->dynamic_entries = true;
		break;

	case ARGP_IPV6:
		if (!str_to_addr6_port(arg, &arguments->bib_addr6))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_IPV4:
		if (!str_to_addr4_port(arg, &arguments->bib_addr4))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_REMOTE6:
		if (!str_to_addr6_port(arg, &arguments->session_pair6.remote))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_LOCAL6:
		if (!str_to_addr6_port(arg, &arguments->session_pair6.local))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_LOCAL4:
		if (!str_to_addr4_port(arg, &arguments->session_pair4.local))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_REMOTE4:
		if (!str_to_addr4_port(arg, &arguments->session_pair4.remote))
			return RESPONSE_PARSE_FAIL;
		break;

	case ARGP_ADF:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= ADDRESS_DEPENDENT_FILTER_MASK;
		if (!str_to_bool(arg, &arguments->filtering.address_dependent_filtering))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_FINFO:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= FILTER_INFO_MASK;
		if (!str_to_bool(arg, &arguments->filtering.filter_informational_icmpv6))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_DROPTCP:
		arguments->mode = MODE_FILTERING;
		arguments->operation |= DROP_TCP_MASK;
		if (!str_to_bool(arg, &arguments->filtering.drop_externally_initiated_tcp_connections))
			return RESPONSE_PARSE_FAIL;
		break;

	case ARGP_HEAD:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= PHR_MASK;
		if (!str_to_u16(arg, &arguments->translate.packet_head_room, 0, 0xFFFF))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_TAIL:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= PTR_MASK;
		if (!str_to_u16(arg, &arguments->translate.packet_tail_room, 0, 0xFFFF))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_O6TCLASS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= OIPV6_MASK;
		if (!str_to_bool(arg, &arguments->translate.override_ipv6_traffic_class))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_O4TCLASS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= OIPV4_MASK;
		if (!str_to_bool(arg, &arguments->translate.override_ipv4_traffic_class))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_4TCLASS:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= IPV4_TRAFFIC_MASK;
		if (!str_to_u8(arg, &arguments->translate.ipv4_traffic_class, 0, 0xFF))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_DF:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= DF_ALWAYS_MASK;
		if (!str_to_bool(arg, &arguments->translate.df_always_set))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_GENID:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= GEN_IPV4_MASK;
		if (!str_to_bool(arg, &arguments->translate.generate_ipv4_id))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_IMP_MTU:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= IMP_MTU_FAIL_MASK;
		if (!str_to_bool(arg, &arguments->translate.improve_mtu_failure_rate))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_MIN_MTU6:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= IPV6_NEXTHOP_MASK;
		if (!str_to_u16(arg, &arguments->translate.ipv6_nexthop_mtu, 0, 0xFFFF))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_MIN_MTU4:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= IPV4_NEXTHOP_MASK;
		if (!str_to_u16(arg, &arguments->translate.ipv4_nexthop_mtu, 0, 0xFFFF))
			return RESPONSE_PARSE_FAIL;
		break;
	case ARGP_PLATEAU:
		arguments->mode = MODE_TRANSLATE;
		arguments->operation |= MTU_PLATEAUS_MASK;
		if (!str_to_u16_array(arg, &arguments->translate.mtu_plateaus,
				&arguments->translate.mtu_plateau_count))
			return RESPONSE_PARSE_FAIL;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/*
 * ARGS_DOC. Field 3 in ARGP.
 * A description of the non-option command-line arguments we accept.
 */
static char args_doc[] = "";

/*
 * DOC.  Field 4 in ARGP.
 * Program documentation. TODO (info) falta.
 */
static char doc[] = "nat64 -- User space program to configure NAT64.\vFrom the GNU C Tutorial.";


/**
 * Uses argp.h to read the parameters from the user, validates them, and returns the result as a
 * structure.
 */
error_t parse_args(int argc, char **argv, struct arguments *result)
{
	error_t parse_result;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(result, 0, sizeof(*result));

	parse_result = argp_parse(&argp, argc, argv, 0, 0, result);
	if (parse_result != 0)
		return parse_result;

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
	error_t result;

	result = parse_args(argc, argv, &args);
	if (result != 0)
		return result;

	switch (args.mode) {
	case ARGP_POOL6:
		switch (args.operation) {
		case ARGP_DISPLAY:
			return pool6_display();
		case ARGP_ADD:
			return pool6_add(&args.pool6_prefix);
		case ARGP_REMOVE:
			return pool6_remove(&args.pool6_prefix);
		default:
			printf("Unknown operation for IPv6 pool mode: %d.", args.operation);
			return RESPONSE_UNKNOWN_OP;
		}
		break;

	case ARGP_POOL4:
		switch (args.operation) {
		case ARGP_DISPLAY:
			return pool4_display();
		case ARGP_ADD:
			return pool4_add(&args.pool4_addr);
		case ARGP_REMOVE:
			return pool4_remove(&args.pool4_addr);
		default:
			printf("Unknown operation for IPv4 pool mode: %d.", args.operation);
			return RESPONSE_UNKNOWN_OP;
		}
	case ARGP_BIB:
		switch (args.operation) {
		case ARGP_DISPLAY:
			return bib_display(args.tcp, args.udp, args.icmp);
		default:
			printf("Unknown operation for BIB mode: %d.", args.operation);
			return RESPONSE_UNKNOWN_OP;
		}
		break;

	case ARGP_SESSION:
		switch (args.operation) {
		case ARGP_DISPLAY:
			return session_display(args.tcp, args.udp, args.icmp);
		case ARGP_ADD:
			return session_add(args.tcp, args.udp, args.icmp, &args.session_pair6,
					&args.session_pair4);
		case ARGP_REMOVE:
			// TODO (warning) This one is starting to annoy me.
//			return session_remove(args.tcp, args.udp, args.icmp, &args.session_pair6,
//					&args.session_pair4);
		default:
			printf("Unknown operation for session mode: %d.", args.operation);
			return RESPONSE_UNKNOWN_OP;
		}
		break;

	case ARGP_FILTERING:
		return filtering_request(args.operation, &args.filtering);

	case ARGP_TRANSLATE:
		result = translate_request(args.operation, &args.translate);
		if (args.translate.mtu_plateaus)
			free(args.translate.mtu_plateaus);
		return result;

	default:
		printf("Could not understand the command at all; Use --help or --usage to see the "
				"command list.\n");
		return RESPONSE_UNKNOWN_MODE;
	}
}
