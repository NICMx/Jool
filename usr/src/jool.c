/**
 * @file
 * Main for the NAT64's userspace application.
 * Parses parameters from the user and hands the real work to the other .c's.
 *
 * @author Miguel González
 * @author Alberto Leiva
 */

#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/config_proto.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/pool6.h"
#include "nat64/usr/pool4.h"
#include "nat64/usr/bib.h"
#include "nat64/usr/session.h"
#include "nat64/usr/general.h"
#ifdef BENCHMARK
#include "nat64/usr/log_time.h"
#endif


const char *argp_program_version = "3.2.2";
const char *argp_program_bug_address = "jool@nic.mx";

/**
 * The parameters received from the user, formatted and ready to be read in any order.
 */
struct arguments {
	enum config_mode mode;
	enum config_operation op;

	struct {
		/* This is actually only common to the pools; the tables don't use it. */
		bool quick;

		struct {
			struct ipv6_prefix prefix;
			bool prefix_set;
		} pool6;

		struct {
			struct in_addr addr;
			bool addr_set;
			unsigned char maskbits;
		} pool4;

		struct {
			bool tcp, udp, icmp;
			bool numeric_hostname;
			bool csv_format;

			struct {
				struct ipv6_transport_addr addr6;
				bool addr6_set;
				struct ipv4_transport_addr addr4;
				bool addr4_set;
			} bib;
		} tables;

	} db;

	struct {
		enum general_module module;
		__u8 type;
		size_t size;
		void *data;
	} general;
};

/**
 * The flags the user can write as program parameters.
 */
enum argp_flags {
	/* Modes */
	ARGP_POOL6 = '6',
	ARGP_POOL4 = '4',
	ARGP_BIB = 'b',
	ARGP_SESSION = 's',
#ifdef BENCHMARK
	ARGP_LOGTIME = 'l',
#endif
	ARGP_GENERAL = 'g',

	/* Operations */
	ARGP_DISPLAY = 'd',
	ARGP_COUNT = 'c',
	ARGP_ADD = 'a',
	ARGP_UPDATE = 5000,
	ARGP_REMOVE = 'r',
	ARGP_FLUSH = 'f',

	/* Pools */
	ARGP_PREFIX = 1000,
	ARGP_ADDRESS = 1001,
	ARGP_QUICK = 'q',

	/* BIB, session */
	ARGP_TCP = 't',
	ARGP_UDP = 'u',
	ARGP_ICMP = 'i',
	ARGP_NUMERIC_HOSTNAME = 'n',
	ARGP_CSV = 2022,
	ARGP_BIB_IPV6 = 2020,
	ARGP_BIB_IPV4 = 2021,

	/* General */
	ARGP_DROP_ADDR = 3000,
	ARGP_DROP_INFO = 3001,
	ARGP_DROP_TCP = 3002,
	ARGP_UDP_TO = 3010,
	ARGP_ICMP_TO = 3011,
	ARGP_TCP_TO = 3012,
	ARGP_TCP_TRANS_TO = 3013,
	ARGP_STORED_PKTS = 3014,
	ARGP_RESET_TCLASS = 4002,
	ARGP_RESET_TOS = 4003,
	ARGP_NEW_TOS = 4004,
	ARGP_DF = 4005,
	ARGP_BUILD_ID = 4006,
	ARGP_LOWER_MTU_FAIL = 4007,
	ARGP_PLATEAUS = 4010,
	ARGP_MIN_IPV6_MTU = 4011,
	ARGP_FRAG_TO = 4012,
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
	{ NULL, 0, NULL, 0, "Configuration targets/modes:", 1 },
	{ "pool6", ARGP_POOL6, NULL, 0, "The command will operate on the IPv6 pool." },
	{ "pool4", ARGP_POOL4, NULL, 0, "The command will operate on the IPv4 pool." },
	{ "bib", ARGP_BIB, NULL, 0, "The command will operate on the BIBs." },
	{ "session", ARGP_SESSION, NULL, 0, "The command will operate on the session tables." },
#ifdef BENCHMARK
	{ "logTime", ARGP_LOGTIME, NULL, 0, "The command will operate on the logs times database."},
#endif
	{ "general", ARGP_GENERAL, NULL, 0, "The command will operate on miscellaneous configuration "
			"values (default)." },

	{ NULL, 0, NULL, 0, "Operations:", 2 },
	{ "display", ARGP_DISPLAY, NULL, 0, "Print the target (default)." },
	{ "count", ARGP_COUNT, NULL, 0, "Print the number of elements in the target." },
	{ "add", ARGP_ADD, NULL, 0, "Add an element to the target." },
	{ "update", ARGP_UPDATE, NULL, 0, "Change something in the target." },
	{ "remove", ARGP_REMOVE, NULL, 0, "Remove an element from the target." },
	{ "flush", ARGP_FLUSH, NULL, 0, "Clear the target." },

	{ NULL, 0, NULL, 0, "IPv4 and IPv6 Pool options:", 3 },
	{ "quick", ARGP_QUICK, NULL, 0, "Do not clean the BIB and/or session tables after removing. "
		"Available on remove and flush operations only. " },

	{ NULL, 0, NULL, 0, "IPv6 Pool-only options:", 4 },
	{ "prefix", ARGP_PREFIX, PREFIX_FORMAT, 0, "The prefix to be added or removed. "
			"Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "IPv4 Pool-only options:", 5 },
	{ "address", ARGP_ADDRESS, IPV4_ADDR_FORMAT, 0, "Address to be added or removed. "
			"Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "BIB & Session options:", 6 },
	{ "icmp", ARGP_ICMP, NULL, 0, "Operate on the ICMP table." },
	{ "tcp", ARGP_TCP, NULL, 0, "Operate on the TCP table." },
	{ "udp", ARGP_UDP, NULL, 0, "Operate on the UDP table." },
	{ "numeric", ARGP_NUMERIC_HOSTNAME, NULL, 0, "Don't resolve names. "
			"Available on display operation only." },
	{ "csv", ARGP_CSV, NULL, 0, "Print in CSV format. "
			"Available on display operation only."},

	{ NULL, 0, NULL, 0, "BIB-only options:", 7 },
	{ "bib6", ARGP_BIB_IPV6, IPV6_TRANSPORT_FORMAT, 0,
			"This is the addres#port of the remote IPv6 node of the entry to be added or removed. "
			"Available on add and remove operations only." },
	{ "bib4", ARGP_BIB_IPV4, IPV4_TRANSPORT_FORMAT, 0,
			"This is the local IPv4 addres#port of the entry to be added or removed. "
			"Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "'General' options:", 8 },
	{ DROP_BY_ADDR_OPT, ARGP_DROP_ADDR, BOOL_FORMAT, 0,
			"Use Address-Dependent Filtering?" },
	{ DROP_ICMP6_INFO_OPT, ARGP_DROP_INFO, BOOL_FORMAT, 0,
			"Filter ICMPv6 Informational packets?" },
	{ DROP_EXTERNAL_TCP_OPT, ARGP_DROP_TCP, BOOL_FORMAT, 0,
			"Drop externally initiated TCP connections?" },
	{ UDP_TIMEOUT_OPT, ARGP_UDP_TO, NUM_FORMAT, 0,
			"Set the timeout for UDP sessions." },
	{ ICMP_TIMEOUT_OPT, ARGP_ICMP_TO, NUM_FORMAT, 0,
			"Set the timeout for ICMP sessions." },
	{ TCP_EST_TIMEOUT_OPT, ARGP_TCP_TO, NUM_FORMAT, 0,
			"Set the established connection idle-timeout for TCP sessions." },
	{ TCP_TRANS_TIMEOUT_OPT, ARGP_TCP_TRANS_TO, NUM_FORMAT, 0,
			"Set the transitory connection idle-timeout for TCP sessions." },
	{ STORED_PKTS_OPT, ARGP_STORED_PKTS, NUM_FORMAT, 0,
			"Set the maximum number of packets Jool should bother to remember while awaiting "
			"simultaneous open of TCP connections." },
	{ RESET_TCLASS_OPT, ARGP_RESET_TCLASS, BOOL_FORMAT, 0,
			"Override IPv6 Traffic class?" },
	{ RESET_TOS_OPT, ARGP_RESET_TOS, BOOL_FORMAT, 0,
			"Override IPv4 Type of Service?" },
	{ NEW_TOS_OPT, ARGP_NEW_TOS, NUM_FORMAT, 0,
			"Set the IPv4 Type of Service." },
	{ DF_ALWAYS_ON_OPT, ARGP_DF, BOOL_FORMAT, 0,
			"Always set Don't Fragment?" },
	{ BUILD_IPV4_ID_OPT, ARGP_BUILD_ID, BOOL_FORMAT, 0,
			"Generate IPv4 ID?" },
	{ LOWER_MTU_FAIL_OPT, ARGP_LOWER_MTU_FAIL, BOOL_FORMAT, 0,
			"Decrease MTU failure rate?" },
	{ MTU_PLATEAUS_OPT, ARGP_PLATEAUS, NUM_ARR_FORMAT, 0,
			"Set the MTU plateaus." },
	{ MIN_IPV6_MTU_OPT, ARGP_MIN_IPV6_MTU, NUM_FORMAT, 0,
			"Set the Minimum IPv6 MTU." },
	{ FRAG_TIMEOUT_OPT, ARGP_FRAG_TO, NUM_FORMAT, 0,
			"Set the timeout for arrival of fragments." },

	{ NULL },
};

static int update_state(struct arguments *args, enum config_mode valid_modes,
		enum config_operation valid_ops)
{
	enum config_mode common_modes;
	enum config_operation common_ops;

	common_modes = args->mode & valid_modes;
	if (!common_modes || (common_modes | valid_modes) != valid_modes)
		goto fail;
	args->mode = common_modes;

	common_ops = args->op & valid_ops;
	if (!common_ops || (common_ops | valid_ops) != valid_ops)
		goto fail;
	args->op = common_ops;

	return 0;

fail:
	log_err("Illegal combination of parameters. See `man jool`.");
	return -EINVAL;
}

static int set_general_arg(struct arguments *args, enum general_module module, __u8 type,
		size_t size, void *value)
{
	int error = update_state(args, MODE_GENERAL, OP_UPDATE);
	if (error)
		return error;

	if (args->general.data) {
		log_err("You can only edit one configuration value at a time.");
		return -EINVAL;
	}

	args->general.module = module;
	args->general.type = type;
	args->general.size = size;
	args->general.data = malloc(size);
	if (!args->general.data)
		return -ENOMEM;
	memcpy(args->general.data, value, size);

	return 0;
}

static int set_general_bool(struct arguments *args, enum general_module module, __u8 type,
		char *value)
{
	__u8 tmp;
	int error;

	error = str_to_bool(value, &tmp);
	if (error)
		return error;

	return set_general_arg(args, module, type, sizeof(tmp), &tmp);
}

static int set_general_u8(struct arguments *args, enum general_module module, __u8 type,
		char *value, __u8 min, __u8 max)
{
	__u8 tmp;
	int error;

	error = str_to_u8(value, &tmp, min, max);
	if (error)
		return error;

	return set_general_arg(args, module, type, sizeof(tmp), &tmp);
}

static int set_general_u16(struct arguments *args, enum general_module module, __u8 type,
		char *value, __u16 min, __u16 max)
{
	__u16 tmp;
	int error;

	error = str_to_u16(value, &tmp, min, max);
	if (error)
		return error;

	return set_general_arg(args, module, type, sizeof(tmp), &tmp);
}

static int set_general_u64(struct arguments *args, enum general_module module, __u8 type,
		char *value, __u64 min, __u64 max, __u64 multiplier)
{
	__u64 tmp;
	int error;

	error = str_to_u64(value, &tmp, min, max);
	if (error)
		return error;
	tmp *= multiplier;

	return set_general_arg(args, module, type, sizeof(tmp), &tmp);
}

static int set_general_u16_array(struct arguments *args, enum general_module module, int type,
		char *value)
{
	__u16* array;
	size_t array_len;
	int error;

	error = str_to_u16_array(value, &array, &array_len);
	if (error)
		return error;

	error = set_general_arg(args, module, type, array_len * sizeof(*array), array);
	free(array);
	return error;
}

/*
 * PARSER. Field 2 in ARGP.
 */
static int parse_opt(int key, char *str, struct argp_state *state)
{
	struct arguments *args = state->input;
	int error = 0;

	switch (key) {
	case ARGP_POOL6:
		error = update_state(args, MODE_POOL6, POOL6_OPS);
		break;
	case ARGP_POOL4:
		error = update_state(args, MODE_POOL4, POOL4_OPS);
		break;
	case ARGP_BIB:
		error = update_state(args, MODE_BIB, BIB_OPS);
		break;
	case ARGP_SESSION:
		error = update_state(args, MODE_SESSION, SESSION_OPS);
		break;
#ifdef BENCHMARK
	case ARGP_LOGTIME:
		error = update_state(args, MODE_LOGTIME, LOGTIME_OPS);
		break;
#endif
	case ARGP_GENERAL:
		error = update_state(args, MODE_GENERAL, GENERAL_OPS);
		break;

	case ARGP_DISPLAY:
		error = update_state(args, DISPLAY_MODES, OP_DISPLAY);
		break;
	case ARGP_COUNT:
		error = update_state(args, COUNT_MODES, OP_COUNT);
		break;
	case ARGP_ADD:
		error = update_state(args, ADD_MODES, OP_ADD);
		break;
	case ARGP_UPDATE:
		error = update_state(args, UPDATE_MODES, OP_UPDATE);
		break;
	case ARGP_REMOVE:
		error = update_state(args, REMOVE_MODES, OP_REMOVE);
		break;
	case ARGP_FLUSH:
		error = update_state(args, FLUSH_MODES, OP_FLUSH);
		break;

	case ARGP_UDP:
		error = update_state(args, MODE_BIB | MODE_SESSION, BIB_OPS | SESSION_OPS);
		args->db.tables.udp = true;
		break;
	case ARGP_TCP:
		error = update_state(args, MODE_BIB | MODE_SESSION, BIB_OPS | SESSION_OPS);
		args->db.tables.tcp = true;
		break;
	case ARGP_ICMP:
		error = update_state(args, MODE_BIB | MODE_SESSION, BIB_OPS | SESSION_OPS);
		args->db.tables.icmp = true;
		break;
	case ARGP_NUMERIC_HOSTNAME:
		error = update_state(args, MODE_BIB | MODE_SESSION, OP_DISPLAY);
		args->db.tables.numeric_hostname = true;
		break;
	case ARGP_CSV:
		error = update_state(args, MODE_BIB | MODE_SESSION, OP_DISPLAY);
		args->db.tables.csv_format = true;
		break;

	case ARGP_ADDRESS:
		error = update_state(args, MODE_POOL4, OP_ADD | OP_REMOVE);
		if (error)
			return error;
		if (strchr(str, '/') != 0){
			error = str_to_addr4_mask(str, &args->db.pool4.addr, &args->db.pool4.maskbits);
		} else {
			error = str_to_addr4(str, &args->db.pool4.addr);
			args->db.pool4.maskbits = NULL;
		}
		args->db.pool4.addr_set = true;
		break;
	case ARGP_PREFIX:
		error = update_state(args, MODE_POOL6, OP_ADD | OP_REMOVE);
		if (error)
			return error;
		error = str_to_prefix(str, &args->db.pool6.prefix);
		args->db.pool6.prefix_set = true;
		break;
	case ARGP_QUICK:
		error = update_state(args, MODE_POOL6 | MODE_POOL4, OP_REMOVE | OP_FLUSH);
		args->db.quick = true;
		break;

	case ARGP_BIB_IPV6:
		error = update_state(args, MODE_BIB, OP_ADD | OP_REMOVE);
		if (error)
			return error;
		error = str_to_addr6_port(str, &args->db.tables.bib.addr6);
		args->db.tables.bib.addr6_set = true;
		break;
	case ARGP_BIB_IPV4:
		error = update_state(args, MODE_BIB, OP_ADD | OP_REMOVE);
		if (error)
			return error;
		error = str_to_addr4_port(str, &args->db.tables.bib.addr4);
		args->db.tables.bib.addr4_set = true;
		break;

	case ARGP_DROP_ADDR:
		error = set_general_bool(args, FILTERING, DROP_BY_ADDR, str);
		break;
	case ARGP_DROP_INFO:
		error = set_general_bool(args, FILTERING, DROP_ICMP6_INFO, str);
		break;
	case ARGP_DROP_TCP:
		error = set_general_bool(args, FILTERING, DROP_EXTERNAL_TCP, str);
		break;
	case ARGP_UDP_TO:
		error = set_general_u64(args, SESSIONDB, UDP_TIMEOUT, str, UDP_MIN, MAX_U32/1000, 1000);
		break;
	case ARGP_ICMP_TO:
		error = set_general_u64(args, SESSIONDB, ICMP_TIMEOUT, str, 0, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TO:
		error = set_general_u64(args, SESSIONDB, TCP_EST_TIMEOUT, str, TCP_EST, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TRANS_TO:
		error = set_general_u64(args, SESSIONDB, TCP_TRANS_TIMEOUT, str, TCP_TRANS, MAX_U32/1000, 1000);
		break;
	case ARGP_STORED_PKTS:
		error = set_general_u64(args, PKTQUEUE, MAX_PKTS, str, 0, MAX_U64, 1);
		break;

	case ARGP_RESET_TCLASS:
		error = set_general_bool(args, TRANSLATE, RESET_TCLASS, str);
		break;
	case ARGP_RESET_TOS:
		error = set_general_bool(args, TRANSLATE, RESET_TOS, str);
		break;
	case ARGP_NEW_TOS:
		error = set_general_u8(args, TRANSLATE, NEW_TOS, str, 0, MAX_U8);
		break;
	case ARGP_DF:
		error = set_general_bool(args, TRANSLATE, DF_ALWAYS_ON, str);
		break;
	case ARGP_BUILD_ID:
		error = set_general_bool(args, TRANSLATE, BUILD_IPV4_ID, str);
		break;
	case ARGP_LOWER_MTU_FAIL:
		error = set_general_bool(args, TRANSLATE, LOWER_MTU_FAIL, str);
		break;
	case ARGP_PLATEAUS:
		error = set_general_u16_array(args, TRANSLATE, MTU_PLATEAUS, str);
		break;
	case ARGP_MIN_IPV6_MTU:
		error = set_general_u16(args, SENDPKT, MIN_IPV6_MTU, str, 1280, MAX_U16);
		break;

	case ARGP_FRAG_TO:
		error = set_general_u64(args, FRAGMENT, FRAGMENT_TIMEOUT, str, FRAGMENT_MIN, MAX_U32/1000, 1000);
		break;

	default:
		error = ARGP_ERR_UNKNOWN;
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
 * Zeroizes all of "num"'s bits, except the last one. Returns the result.
 */
static unsigned int zeroize_upper_bits(__u8 num)
{
	__u8 mask = 0x01;

	do {
		if ((num & mask) != 0)
			return num & mask;
		mask <<= 1;
	} while (mask);

	return num;
}

/**
 * Uses argp.h to read the parameters from the user, validates them, and returns the result as a
 * structure.
 */
static int parse_args(int argc, char **argv, struct arguments *result)
{
	int error;
	struct argp argp = { options, parse_opt, args_doc, doc };

	memset(result, 0, sizeof(*result));
	result->mode = 0xFF;
	result->op = 0xFF;

	error = argp_parse(&argp, argc, argv, 0, NULL, result);
	if (error)
		return error;

	result->mode = zeroize_upper_bits(result->mode);
	result->op = zeroize_upper_bits(result->op);

	if (!result->db.tables.tcp && !result->db.tables.udp && !result->db.tables.icmp) {
		result->db.tables.tcp = true;
		result->db.tables.udp = true;
		result->db.tables.icmp = true;
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
		switch (args.op) {
		case OP_DISPLAY:
			return pool6_display();
		case OP_COUNT:
			return pool6_count();
		case OP_ADD:
			if (!args.db.pool6.prefix_set) {
				log_err("Please enter the prefix to be added (--prefix).");
				return -EINVAL;
			}
			return pool6_add(&args.db.pool6.prefix);
		case OP_REMOVE:
			if (!args.db.pool6.prefix_set) {
				log_err("Please enter the prefix to be removed (--prefix).");
				return -EINVAL;
			}
			return pool6_remove(&args.db.pool6.prefix, args.db.quick);
		case OP_FLUSH:
			return pool6_flush(args.db.quick);
		default:
			log_err("Unknown operation for IPv6 pool mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_POOL4:
		switch (args.op) {
		case OP_DISPLAY:
			return pool4_display();
		case OP_COUNT:
			return pool4_count();
		case OP_ADD:
			if (!args.db.pool4.addr_set) {
				log_err("Please enter the address to be added (--address).");
				return -EINVAL;
			}
			return pool4_add(&args.db.pool4.addr, &args.db.pool4.maskbits);
		case OP_REMOVE:
			if (!args.db.pool4.addr_set) {
				log_err("Please enter the address to be removed (--address).");
				return -EINVAL;
			}
			return pool4_remove(&args.db.pool4.addr, args.db.quick);
		case OP_FLUSH:
			return pool4_flush(args.db.quick);
		default:
			log_err("Unknown operation for IPv4 pool mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_BIB:
		switch (args.op) {
		case OP_DISPLAY:
			return bib_display(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.numeric_hostname, args.db.tables.csv_format);
		case OP_COUNT:
			return bib_count(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp);

		case OP_ADD:
			error = 0;
			if (!args.db.tables.bib.addr6_set) {
				log_err("Missing IPv6 address#port (--bib6).");
				error = -EINVAL;
			}
			if (!args.db.tables.bib.addr4_set) {
				log_err("Missing IPv4 address#port (--bib4).");
				error = -EINVAL;
			}
			if (error)
				return error;

			return bib_add(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					&args.db.tables.bib.addr6, &args.db.tables.bib.addr4);

		case OP_REMOVE:
			if (!args.db.tables.bib.addr6_set && !args.db.tables.bib.addr4_set) {
				log_err("I need the IPv4 transport address and/or the IPv6 transport address of "
						"the entry you want to remove.");
				return -EINVAL;
			}
			return bib_remove(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.bib.addr6_set, &args.db.tables.bib.addr6,
					args.db.tables.bib.addr4_set, &args.db.tables.bib.addr4);

		default:
			log_err("Unknown operation for session mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_SESSION:
		switch (args.op) {
		case OP_DISPLAY:
			return session_display(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.numeric_hostname, args.db.tables.csv_format);
		case OP_COUNT:
			return session_count(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp);
		default:
			log_err("Unknown operation for session mode: %u.", args.op);
			return -EINVAL;
		}
		break;
#ifdef BENCHMARK
	case MODE_LOGTIME:
		switch (args.op) {
		case OP_DISPLAY:
			return logtime_display();
			break;
		default:
			log_err("Unknown operation for log time mode: %u.", args.op);
			break;
		}
		break;
#endif

	case MODE_GENERAL:
		switch (args.op) {
		case OP_DISPLAY:
			return general_display();
		case OP_UPDATE:
			error = general_update(args.general.module, args.general.type, args.general.size,
					args.general.data);
			free(args.general.data);
			return error;
		default:
			log_err("Unknown operation for general mode: %u.", args.op);
			return -EINVAL;
		}
	}

	log_err("Unknown configuration mode: %u", args.mode);
	return -EINVAL;
}

int main(int argc, char **argv)
{
	return -main_wrapped(argc, argv);
}
