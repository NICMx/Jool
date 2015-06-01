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

#include "nat64/common/constants.h"
#include "nat64/common/config.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/pool6.h"
#include "nat64/usr/pool4.h"
#include "nat64/usr/bib.h"
#include "nat64/usr/session.h"
#include "nat64/usr/eam.h"
#include "nat64/usr/global.h"
#include "nat64/usr/log_time.h"


const char *argp_program_version = JOOL_VERSION_STR;
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
			__u32 mark;
			struct ipv4_prefix prefix;
			struct port_range ports;
			bool prefix_set;
		} pool4;

		struct {
			bool tcp, udp, icmp;
			bool numeric;
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
		__u8 type;
		size_t size;
		void *data;
	} global;
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
	ARGP_EAMT = 'e',
	ARGP_BLACKLIST = 7000,
	ARGP_RFC6791 = 6791,
	ARGP_LOGTIME = 'l',
	ARGP_GLOBAL = 'g',

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
	ARGP_MARK = 'm',

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
	ARGP_SRC_ICMP6ERRS_BETTER = 3015,
	ARGP_BIB_LOGGING,
	ARGP_SESSION_LOGGING,
	ARGP_RESET_TCLASS = 4002,
	ARGP_RESET_TOS = 4003,
	ARGP_NEW_TOS = 4004,
	ARGP_DF = 4005,
	ARGP_BUILD_FH = 4006,
	ARGP_BUILD_ID = 4007,
	ARGP_LOWER_MTU_FAIL = 4008,
	ARGP_PLATEAUS = 4010,
	ARGP_FRAG_TO = 4012,
	ARGP_ENABLE_TRANSLATION = 4013,
	ARGP_DISABLE_TRANSLATION = 4014,
	ARGP_COMPUTE_CSUM_ZERO = 4015,
	ARGP_RANDOMIZE_RFC6791 = 4017,
	ARGP_ATOMIC_FRAGMENTS = 4016,
};

#define BOOL_FORMAT "BOOL"
#define NUM_FORMAT "NUM"
#define NUM_ARRAY_FORMAT "NUM[,NUM]*"
#define PREFIX6_FORMAT "ADDR6/NUM"
#define PREFIX4_FORMAT "ADDR4/NUM"
#define TRANSPORT6_FORMAT "ADDR6#NUM"
#define TRANSPORT4_FORMAT "ADDR4#NUM"

/*
 * OPTIONS. Field 1 in ARGP.
 * Order of fields: { NAME, KEY, ARG, FLAGS, DOC }.
 */
static struct argp_option options[] =
{
	{ NULL, 0, NULL, 0, "Address specification: ", 1},
	{ NULL, 0, NULL, OPTION_DOC, "Address may be specified as one IPv4 prefix/transport format "
			"and/or one IPv6 prefix/transport format."},

	{ NULL, 0, NULL, 0, "Configuration targets/modes:", 2 },
	{ "pool6", ARGP_POOL6, NULL, 0, "The command will operate on the IPv6 prefix pool." },
#ifdef STATEFUL
	{ "pool4", ARGP_POOL4, NULL, 0, "The command will operate on the IPv4 address pool." },
	{ "bib", ARGP_BIB, NULL, 0, "The command will operate on the BIBs." },
	{ "session", ARGP_SESSION, NULL, 0, "The command will operate on the session tables." },
#else
	{ "eamt", ARGP_EAMT, NULL, 0, "The command will operate on the EAM table."},
	{ "blacklist", ARGP_BLACKLIST, NULL, 0, "The command will operate on the IPv4 prefix "
			"blacklist." },
	{ "pool6791", ARGP_RFC6791, NULL, 0, "The command will operate on the RFC6791 pool."},
#endif
#ifdef BENCHMARK
	{ "logTime", ARGP_LOGTIME, NULL, 0, "The command will operate on the logs times database."},
#endif
	{ "global", ARGP_GLOBAL, NULL, 0, "The command will operate on miscellaneous configuration "
			"values (default)." },
	{ "general", 0, NULL, OPTION_ALIAS, ""},

	{ NULL, 0, NULL, 0, "Operations:", 3 },
	{ "display", ARGP_DISPLAY, NULL, 0, "Print the target (default)." },
	{ "count", ARGP_COUNT, NULL, 0, "Print the number of elements in the target." },
	{ "add", ARGP_ADD, NULL, 0, "Add an element to the target." },
	{ "update", ARGP_UPDATE, NULL, 0, "Change something in the target." },
	{ "remove", ARGP_REMOVE, NULL, 0, "Remove an element from the target." },
	{ "flush", ARGP_FLUSH, NULL, 0, "Clear the target." },

#ifdef STATEFUL
	{ NULL, 0, NULL, 0, "IPv4 and IPv6 Pool options:", 4 },
	{ "quick", ARGP_QUICK, NULL, 0, "Do not clean the BIB and/or session tables after removing. "
			"Available on remove and flush operations only." },

	{ NULL, 0, NULL, 0, "IPv4 Pool only options:", 4 },
	{ "mark", ARGP_MARK, NUM_FORMAT, 0,
			"Only packets carrying this mark will match this pool4 entry. "
			"Available on add and remove operations only." },

	{ NULL, 0, NULL, 0, "BIB & Session options:", 5 },
	{ "icmp", ARGP_ICMP, NULL, 0, "Operate on the ICMP table." },
	{ "tcp", ARGP_TCP, NULL, 0, "Operate on the TCP table." },
	{ "udp", ARGP_UDP, NULL, 0, "Operate on the UDP table." },
	{ "numeric", ARGP_NUMERIC_HOSTNAME, NULL, 0, "Don't resolve names. "
			"Available on display operation only." },
	{ "csv", ARGP_CSV, NULL, 0, "Print in CSV format. "
			"Available on display operation only."},

#else
	{ NULL, 0, NULL, 0, "EAMT only options:", 4 },
	{ "csv", ARGP_CSV, NULL, 0, "Print in CSV format. "
			"Available on display operation only."},
#endif

	{ NULL, 0, NULL, 0, "'Global' options:", 6 },
	{ OPTNAME_ENABLE, ARGP_ENABLE_TRANSLATION, NULL, 0, "Resume translation of packets.\n" },
	{ OPTNAME_DISABLE, ARGP_DISABLE_TRANSLATION, NULL, 0, "Pause translation of packets.\n" },
	{ OPTNAME_ZEROIZE_TC, ARGP_RESET_TCLASS, BOOL_FORMAT, 0,
			"Always set the IPv6 header's 'Traffic Class' field as zero? "
			"Otherwise copy from IPv4 header's 'TOS'.\n" },
	{ "setTC", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_OVERRIDE_TOS, ARGP_RESET_TOS, BOOL_FORMAT, 0,
			"Override the IPv4 header's 'TOS' field as --tos? "
			"Otherwise copy from IPv6 header's 'Traffic Class'.\n" },
	{ "setTOS", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_TOS, ARGP_NEW_TOS, NUM_FORMAT, 0,
			"Value to override TOS as (only when --override-tos is ON).\n" },
	{ "TOS", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_MTU_PLATEAUS, ARGP_PLATEAUS, NUM_ARRAY_FORMAT, 0,
			"Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.\n" },
	{ "plateaus", 0, NULL, OPTION_ALIAS, ""},
#ifdef STATEFUL
	{ OPTNAME_DROP_BY_ADDR, ARGP_DROP_ADDR, BOOL_FORMAT, 0,
			"Use Address-Dependent Filtering? "
			"ON is (address)-restricted-cone NAT, OFF is full-cone NAT.\n"},
	{ "dropAddr", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_DROP_ICMP6_INFO, ARGP_DROP_INFO, BOOL_FORMAT, 0,
			"Filter ICMPv6 Informational packets?\n" },
	{ "dropInfo", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_DROP_EXTERNAL_TCP, ARGP_DROP_TCP, BOOL_FORMAT, 0,
			"Drop externally initiated TCP connections?\n" },
	{ "dropTCP", 0, NULL, OPTION_ALIAS, ""},

	{ OPTNAME_UDP_TIMEOUT, ARGP_UDP_TO, NUM_FORMAT, 0,
			"Set the UDP session lifetime (in seconds).\n" },
	{ "toUDP", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_ICMP_TIMEOUT, ARGP_ICMP_TO, NUM_FORMAT, 0,
			"Set the timeout for ICMP sessions.\n" },
	{ "toICMP", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_TCPEST_TIMEOUT, ARGP_TCP_TO, NUM_FORMAT, 0,
			"Set the TCP established session lifetime (in seconds).\n" },
	{ "toTCPest", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_TCPTRANS_TIMEOUT, ARGP_TCP_TRANS_TO, NUM_FORMAT, 0,
			"Set the TCP transitory session lifetime (in seconds).\n" },
	{ "toTCPtrans", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_FRAG_TIMEOUT, ARGP_FRAG_TO, NUM_FORMAT, 0,
			"Set the timeout for arrival of fragments.\n" },
	{ "toFrag", 0, NULL, OPTION_ALIAS, ""},

	{ OPTNAME_MAX_SO, ARGP_STORED_PKTS, NUM_FORMAT, 0,
			"Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.\n" },
	{ "maxStoredPkts", 0, NULL, OPTION_ALIAS, ""},
	{ OPTNAME_SRC_ICMP6E_BETTER, ARGP_SRC_ICMP6ERRS_BETTER, BOOL_FORMAT, 0,
			"Translate source addresses directly on 4-to-6 ICMP errors?\n" },

	{ OPTNAME_BIB_LOGGING, ARGP_BIB_LOGGING, BOOL_FORMAT, 0,
			"Log BIBs as they are created and destroyed?\n" },
	{ OPTNAME_SESSION_LOGGING, ARGP_SESSION_LOGGING, BOOL_FORMAT, 0,
			"Log sessions as they are created and destroyed?\n" },
#else
	{ OPTNAME_AMEND_UDP_CSUM, ARGP_COMPUTE_CSUM_ZERO, BOOL_FORMAT, 0,
			"Compute the UDP checksum of IPv4-UDP packets whose value is zero? "
			"Otherwise drop the packet.\n" },
	{ OPTNAME_RANDOMIZE_RFC6791, ARGP_RANDOMIZE_RFC6791, BOOL_FORMAT, 0,
			"Randomize selection of address from the RFC6791 pool? "
			"Otherwise choose the 'Hop Limit'th address.\n" },
#endif

	{ NULL, 0, NULL, 0, "Deprecated options:", 7 },

	{ OPTNAME_ALLOW_ATOMIC_FRAGS, ARGP_ATOMIC_FRAGMENTS, BOOL_FORMAT, 0,
			"Allow atomic fragments?" },
	{ OPTNAME_DF_ALWAYS_ON, ARGP_DF, BOOL_FORMAT, 0,
			"Always set Don't Fragment?" },
	{ OPTNAME_GENERATE_FH, ARGP_BUILD_FH, BOOL_FORMAT, 0,
			"Also include IPv6 Fragment Header when IPv4 Packet DF Flag is not set?" },
	{ OPTNAME_GENERATE_ID4, ARGP_BUILD_ID, BOOL_FORMAT, 0,
			"Generate IPv4 identification?" },
	{ OPTNAME_FIX_ILLEGAL_MTUS, ARGP_LOWER_MTU_FAIL, BOOL_FORMAT, 0,
			"Decrease MTU failure rate?" },

#ifdef STATEFUL
	{ "prefix", ARGP_PREFIX, PREFIX6_FORMAT, 0, "Prefix to be added to or removed from "
			"the IPv6 pool. You no longer need to name this." },
	{ "address", ARGP_ADDRESS, PREFIX4_FORMAT, 0, "'Address' to be added to or removed from "
			"the IPv4 pool. You no longer need to name this." },
	{ "bib6", ARGP_BIB_IPV6, TRANSPORT6_FORMAT, 0,
			"This is the addres#port of the remote IPv6 node of the entry to be added or removed. "
			"You no longer need to name this." },
	{ "bib4", ARGP_BIB_IPV4, TRANSPORT4_FORMAT, 0,
			"This is the local IPv4 addres#port of the entry to be added or removed. "
			"You no longer need to name this." },
#endif
	{ NULL },
};

static int update_state(struct arguments *args, enum config_mode valid_modes,
		enum config_operation valid_ops)
{
	enum config_mode common_modes;
	enum config_operation common_ops;

	valid_modes &= nat64_is_stateful() ? NAT64_MODES : SIIT_MODES;

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
	log_err("Illegal combination of parameters. See the manpage for readable grammar.");
	return -EINVAL;
}

static int set_global_arg(struct arguments *args, __u8 type, size_t size, void *value)
{
	int error = update_state(args, MODE_GLOBAL, OP_UPDATE);
	if (error)
		return error;

	if (args->global.data) {
		log_err("You can only edit one global configuration value at a time.");
		return -EINVAL;
	}

	args->global.type = type;
	args->global.size = size;
	args->global.data = malloc(size);
	if (!args->global.data)
		return -ENOMEM;
	memcpy(args->global.data, value, size);

	return 0;
}

static int set_global_bool(struct arguments *args, __u8 type, char *value)
{
	__u8 tmp;
	int error;

	error = str_to_bool(value, &tmp);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

static int set_global_u8(struct arguments *args, __u8 type, char *value, __u8 min, __u8 max)
{
	__u8 tmp;
	int error;

	error = str_to_u8(value, &tmp, min, max);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

#ifdef STATEFUL
static int set_global_u64(struct arguments *args, __u8 type, char *value, __u64 min, __u64 max,
		__u64 multiplier)
{
	__u64 tmp;
	int error;

	error = str_to_u64(value, &tmp, min, max);
	if (error)
		return error;
	tmp *= multiplier;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}
#endif

static int set_global_u16_array(struct arguments *args, int type, char *value)
{
	__u16* array;
	size_t array_len;
	int error;

	error = str_to_u16_array(value, &array, &array_len);
	if (error)
		return error;

	error = set_global_arg(args, type, array_len * sizeof(*array), array);
	free(array);
	return error;
}

static int set_ipv4_prefix(struct arguments *args, char *str)
{
	int error;

	error = update_state(args, MODE_POOL4 | MODE_BLACKLIST | MODE_RFC6791 | MODE_EAMT,
			OP_ADD | OP_REMOVE);
	if (error)
		return error;

	if (args->db.pool4.prefix_set) {
		log_err("Only one IPv4 prefix can be added or removed at a time.");
		return -EINVAL;
	}

	args->db.pool4.prefix_set = true;
	error = str_to_ipv4_prefix(str, &args->db.pool4.prefix);

	if (!error && nat64_is_stateful() && args->db.pool4.prefix.len < 16) {
		log_debug("Warning: That's a lot of addresses. "
				"Are you sure that /%u is not a typo?",
				args->db.pool4.prefix.len);
	}

	return error;
}

static int set_ipv6_prefix(struct arguments *args, char *str)
{
	int error;

	error = update_state(args, MODE_POOL6 | MODE_EAMT, OP_ADD | OP_UPDATE | OP_REMOVE);
	if (error)
		return error;

	if (args->db.pool6.prefix_set) {
		log_err("Only one IPv6 prefix can be added or removed at a time.");
		return -EINVAL;
	}

	args->db.pool6.prefix_set = true;
	return str_to_ipv6_prefix(str, &args->db.pool6.prefix);
}

static int set_bib6(struct arguments *args, char *str)
{
	int error;

	if (nat64_is_stateless()) {
		log_err("You entered an IPv6 transport address. SIIT doesn't have BIBs...");
		return -EINVAL;
	}

	error = update_state(args, MODE_BIB, OP_ADD | OP_REMOVE);
	if (error)
		return error;

	if (args->db.tables.bib.addr6_set) {
		log_err("You entered more than one IPv6 transport address. "
				"Only one BIB entry can be added or removed at a time.");
		return -EINVAL;
	}

	args->db.tables.bib.addr6_set = true;
	return str_to_addr6_port(str, &args->db.tables.bib.addr6);
}

static int set_bib4(struct arguments *args, char *str)
{
	int error;

	if (nat64_is_stateless()) {
		log_err("You entered an IPv4 transport address. SIIT doesn't have BIBs...");
		return -EINVAL;
	}

	error = update_state(args, MODE_BIB, OP_ADD | OP_REMOVE);
	if (error)
		return error;

	if (args->db.tables.bib.addr4_set) {
		log_err("You entered more than one IPv4 transport address. "
				"Only one BIB entry can be added or removed at a time.");
		return -EINVAL;
	}

	args->db.tables.bib.addr4_set = true;
	return str_to_addr4_port(str, &args->db.tables.bib.addr4);
}

static int set_port_range(struct arguments *args, char *str)
{
	int error;

	if (nat64_is_stateless()) {
		log_err("You seem to have entered a port range. "
				"SIIT doesn't need them...");
		return -EINVAL;
	}

	error = update_state(args, MODE_POOL4, OP_ADD | OP_REMOVE);
	if (error)
		return error;

	return str_to_port_range(str, &args->db.pool4.ports);
}

static int set_ip_args(struct arguments *args, char *str)
{
	int error;

	if (!str)
		return 0;

	if (strlen(str) == 0)
		return 0;

	if (strchr(str, ':')) { /* Token is an IPv6 thingy. */
		if (strchr(str, '#')) { /* Token is a BIB entry. */
			error = set_bib6(args, str);
		} else { /* Just an IPv6 Prefix. */
			error = set_ipv6_prefix(args, str);
		}

	} else if (strchr(str, '.')) { /* Token is an IPv4 thingy. */
		if (strchr(str, '#')) { /* Token is a BIB entry. */
			error = set_bib4(args, str);
		} else { /* Just an IPv4 Prefix */
			error = set_ipv4_prefix(args, str);
		}

	} else { /* Token is a port range. */
		error = set_port_range(args, str);
	}

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
	case ARGP_GLOBAL:
		error = update_state(args, MODE_GLOBAL, GLOBAL_OPS);
		break;
	case ARGP_POOL6:
		error = update_state(args, MODE_POOL6, POOL6_OPS);
		break;
	case ARGP_POOL4:
		error = update_state(args, MODE_POOL4, POOL4_OPS);
		break;
	case ARGP_BLACKLIST:
		error = update_state(args, MODE_BLACKLIST, BLACKLIST_OPS);
		break;
	case ARGP_RFC6791:
		error = update_state(args, MODE_RFC6791, RFC6791_OPS);
		break;
	case ARGP_EAMT:
		error = update_state(args, MODE_EAMT, EAMT_OPS);
		break;
	case ARGP_BIB:
		error = update_state(args, MODE_BIB, BIB_OPS);
		break;
	case ARGP_SESSION:
		error = update_state(args, MODE_SESSION, SESSION_OPS);
		break;
	case ARGP_LOGTIME:
		error = update_state(args, MODE_LOGTIME, LOGTIME_OPS);
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
		args->db.tables.numeric = true;
		break;
	case ARGP_CSV:
		error = update_state(args, MODE_EAMT | MODE_BIB | MODE_SESSION, OP_DISPLAY);
		args->db.tables.csv_format = true;
		break;

	case ARGP_QUICK:
		error = update_state(args, MODE_POOL6 | MODE_POOL4, OP_REMOVE | OP_FLUSH);
		args->db.quick = true;
		break;
	case ARGP_MARK:
		error = update_state(args, MODE_POOL4, OP_ADD | OP_REMOVE);
		if (!error)
			error = str_to_u32(str, &args->db.pool4.mark, 0, MAX_U32);
		break;

	case ARGP_BIB_IPV6:
		error = set_bib6(args, str);
		break;
	case ARGP_BIB_IPV4:
		error = set_bib4(args, str);
		break;

#ifdef STATEFUL
	case ARGP_DROP_ADDR:
		error = set_global_bool(args, DROP_BY_ADDR, str);
		break;
	case ARGP_DROP_INFO:
		error = set_global_bool(args, DROP_ICMP6_INFO, str);
		break;
	case ARGP_DROP_TCP:
		error = set_global_bool(args, DROP_EXTERNAL_TCP, str);
		break;

	case ARGP_UDP_TO:
		error = set_global_u64(args, UDP_TIMEOUT, str, UDP_MIN, MAX_U32/1000, 1000);
		break;
	case ARGP_ICMP_TO:
		error = set_global_u64(args, ICMP_TIMEOUT, str, 0, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TO:
		error = set_global_u64(args, TCP_EST_TIMEOUT, str, TCP_EST, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TRANS_TO:
		error = set_global_u64(args, TCP_TRANS_TIMEOUT, str, TCP_TRANS, MAX_U32/1000, 1000);
		break;
	case ARGP_FRAG_TO:
		error = set_global_u64(args, FRAGMENT_TIMEOUT, str, FRAGMENT_MIN, MAX_U32/1000, 1000);
		break;

	case ARGP_STORED_PKTS:
		error = set_global_u64(args, MAX_PKTS, str, 0, MAX_U64, 1);
		break;
	case ARGP_SRC_ICMP6ERRS_BETTER:
		error = set_global_bool(args, SRC_ICMP6ERRS_BETTER, str);
		break;

	case ARGP_BIB_LOGGING:
		error = set_global_bool(args, BIB_LOGGING, str);
		break;
	case ARGP_SESSION_LOGGING:
		error = set_global_bool(args, SESSION_LOGGING, str);
		break;
#else
	case ARGP_COMPUTE_CSUM_ZERO:
		error = set_global_bool(args, COMPUTE_UDP_CSUM_ZERO, str);
		break;
	case ARGP_RANDOMIZE_RFC6791:
		error = set_global_bool(args, RANDOMIZE_RFC6791, str);
		break;
#endif

	case ARGP_PREFIX:
		error = set_ipv6_prefix(args, str);
		break;
	case ARGP_ADDRESS:
		error = set_ipv4_prefix(args, str);
		break;

	case ARGP_RESET_TCLASS:
		error = set_global_bool(args, RESET_TCLASS, str);
		break;
	case ARGP_RESET_TOS:
		error = set_global_bool(args, RESET_TOS, str);
		break;
	case ARGP_NEW_TOS:
		error = set_global_u8(args, NEW_TOS, str, 0, MAX_U8);
		break;
	case ARGP_DF:
		error = set_global_bool(args, DF_ALWAYS_ON, str);
		break;
	case ARGP_BUILD_FH:
		error = set_global_bool(args, BUILD_IPV6_FH, str);
		break;
	case ARGP_BUILD_ID:
		error = set_global_bool(args, BUILD_IPV4_ID, str);
		break;
	case ARGP_LOWER_MTU_FAIL:
		error = set_global_bool(args, LOWER_MTU_FAIL, str);
		break;
	case ARGP_PLATEAUS:
		error = set_global_u16_array(args, MTU_PLATEAUS, str);
		break;
	case ARGP_ENABLE_TRANSLATION:
		error = set_global_bool(args, ENABLE, "true");
		break;
	case ARGP_DISABLE_TRANSLATION:
		error = set_global_bool(args, DISABLE, "true");
		break;
	case ARGP_ATOMIC_FRAGMENTS:
		error = set_global_bool(args, ATOMIC_FRAGMENTS, str);
		break;
	case ARGP_KEY_ARG:
		error = set_ip_args(args, str);
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
static char args_doc[] = "{address specification}";

/*
 * DOC. Field 4 in ARGP.
 * Program documentation.
 */
static char doc[] = "See the manpage for prettier grammar.\v";

/**
 * Zeroizes all of "num"'s bits, except the last one. Returns the result.
 */
static unsigned int zeroize_upper_bits(__u16 num)
{
	__u16 mask = 0x01;

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
	result->mode = 0xFFFF;
	result->op = 0xFF;
	result->db.pool4.ports.min = 60000U;
	result->db.pool4.ports.max = 65535U;

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

static bool validate_pool6(struct arguments *args)
{
	__u8 valid_lengths[] = POOL6_PREFIX_LENGTHS;
	int valid_lengths_size = sizeof(valid_lengths) / sizeof(valid_lengths[0]);
	int i;

	if (!args->db.pool6.prefix_set) {
		log_err("Please enter the prefix to be added or removed (%s).", PREFIX6_FORMAT);
		return -EINVAL;
	}

	for (i = 0; i < valid_lengths_size; i++) {
		if (args->db.pool6.prefix.len == valid_lengths[i])
			return 0;
	}

	log_err("RFC 6052 does not like prefix length %u.",args->db.pool6.prefix.len);
	printf("These are valid: ");
	for (i = 0; i < valid_lengths_size - 1; i++)
		printf("%u, ", valid_lengths[i]);
	printf("%u.\n", valid_lengths[i]);

	return -EINVAL;
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
		case OP_ADD:
		case OP_UPDATE:
			error = validate_pool6(&args);
			return error ? : pool6_add(&args.db.pool6.prefix);
		case OP_REMOVE:
			error = validate_pool6(&args);
			return error ? : pool6_remove(&args.db.pool6.prefix, args.db.quick);
		case OP_COUNT:
			return pool6_count();
		case OP_FLUSH:
			return pool6_flush(args.db.quick);
		default:
			log_err("Unknown operation for IPv6 pool mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_POOL4:
	case MODE_BLACKLIST:
	case MODE_RFC6791:
		switch (args.op) {
		case OP_DISPLAY:
			return pool4_display(args.mode);
		case OP_COUNT:
			return pool4_count(args.mode);
		case OP_ADD:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be added (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool4_add(args.mode, args.db.pool4.mark,
					&args.db.pool4.prefix,
					&args.db.pool4.ports);
		case OP_REMOVE:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be removed (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool4_remove(args.mode, args.db.pool4.mark,
					&args.db.pool4.prefix,
					&args.db.pool4.ports, args.db.quick);
		case OP_FLUSH:
			return pool4_flush(args.mode, args.db.quick);
		default:
			log_err("Unknown operation for IPv4 pool mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_BIB:
		if (nat64_is_stateless()) {
			log_err("SIIT doesn't have BIBs.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return bib_display(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.numeric, args.db.tables.csv_format);
		case OP_COUNT:
			return bib_count(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp);

		case OP_ADD:
			error = 0;
			if (!args.db.tables.bib.addr6_set) {
				log_err("Missing IPv6 transport address.");
				error = -EINVAL;
			}
			if (!args.db.tables.bib.addr4_set) {
				log_err("Missing IPv4 transport address.");
				error = -EINVAL;
			}
			if (error)
				return error;

			return bib_add(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					&args.db.tables.bib.addr6, &args.db.tables.bib.addr4);

		case OP_REMOVE:
			if (!args.db.tables.bib.addr6_set && !args.db.tables.bib.addr4_set) {
				log_err("Missing IPv4 transport address and/or IPv6 transport address.");
				return -EINVAL;
			}
			return bib_remove(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.bib.addr6_set, &args.db.tables.bib.addr6,
					args.db.tables.bib.addr4_set, &args.db.tables.bib.addr4);

		default:
			log_err("Unknown operation for BIB mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_SESSION:
		if (nat64_is_stateless()) {
			log_err("SIIT doesn't have sessions.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return session_display(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp,
					args.db.tables.numeric, args.db.tables.csv_format);
		case OP_COUNT:
			return session_count(args.db.tables.tcp, args.db.tables.udp, args.db.tables.icmp);
		default:
			log_err("Unknown operation for session mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_EAMT:
		if (nat64_is_stateful()) {
			log_err("Stateful NAT64 doesn't have EAMTs.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return eam_display(args.db.tables.csv_format);
		case OP_COUNT:
			return eam_count();
		case OP_ADD:
			if (!args.db.pool6.prefix_set || !args.db.pool4.prefix_set) {
				log_err("I need the IPv4 prefix and the IPv6 prefix of the entry you want to add.");
				return -EINVAL;
			}
			return eam_add(&args.db.pool6.prefix, &args.db.pool4.prefix);
		case OP_REMOVE:
			if (!args.db.pool6.prefix_set && !args.db.pool4.prefix_set) {
				log_err("I need the IPv4 prefix and/or the IPv6 prefix of the entry you want to "
						"remove.");
				return -EINVAL;
			}
			return eam_remove(args.db.pool6.prefix_set, &args.db.pool6.prefix,
					args.db.pool4.prefix_set, &args.db.pool4.prefix);
		case OP_FLUSH:
			return eam_flush();
		default:
			log_err("Unknown operation for EAMT mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_LOGTIME:
		if (!is_logtime_enabled()) {
			log_err("This is benchmark configuration mode despite benchmark being disabled.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return logtime_display();
		default:
			log_err("Unknown operation for log time mode: %u.", args.op);
			break;
		}
		break;

	case MODE_GLOBAL:
		switch (args.op) {
		case OP_DISPLAY:
			return global_display();
		case OP_UPDATE:
			error = global_update(args.global.type, args.global.size, args.global.data);
			free(args.global.data);
			return error;
		default:
			log_err("Unknown operation for global mode: %u.", args.op);
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
