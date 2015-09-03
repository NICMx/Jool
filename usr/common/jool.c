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
#include "nat64/common/JsonReader.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/pool.h"
#include "nat64/usr/pool6.h"
#include "nat64/usr/pool4.h"
#include "nat64/usr/bib.h"
#include "nat64/usr/session.h"
#include "nat64/usr/eam.h"
#include "nat64/usr/global.h"
#include "nat64/usr/log_time.h"
#include "nat64/usr/argp/options.h"
#include "nat64/usr/netlink.h"



const char *argp_program_version = XLAT_VERSION_STR;
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
			bool force;
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

        struct {
		char *filename;
	} parse_file;
};

static int update_state(struct arguments *args, enum config_mode valid_modes,
		enum config_operation valid_ops)
{
	enum config_mode common_modes;
	enum config_operation common_ops;

	valid_modes &= xlat_is_nat64() ? NAT64_MODES : SIIT_MODES;

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
	return str_to_ipv4_prefix(str, &args->db.pool4.prefix);
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

	if (xlat_is_siit()) {
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

	if (xlat_is_siit()) {
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

	if (xlat_is_siit()) {
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
	case ARGP_FORCE:
		error = update_state(args, MODE_POOL4, OP_ADD);
		args->db.pool4.force = true;
		break;

	case ARGP_BIB_IPV6:
		error = set_bib6(args, str);
		break;
	case ARGP_BIB_IPV4:
		error = set_bib4(args, str);
		break;

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

	case ARGP_COMPUTE_CSUM_ZERO:
		error = set_global_bool(args, COMPUTE_UDP_CSUM_ZERO, str);
		break;
	case ARGP_EAM_HAIRPIN_MODE:
		error = set_global_u8(args, EAM_HAIRPINNING_MODE, str, 0,
				EAM_HAIRPIN_MODE_COUNT - 1);
		break;
	case ARGP_RANDOMIZE_RFC6791:
		error = set_global_bool(args, RANDOMIZE_RFC6791, str);
		break;

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
        case ARGP_PARSE_FILE:

	    error = update_state(args, MODE_PARSE_FILE, OP_UPDATE);

	    args->parse_file.filename =  malloc(sizeof(char)*(strlen(str)+1));


	    if(!args->parse_file.filename) {
	    	error = -ENOMEM;
	        log_err("Unable to allocate memory!.");
	        break;
	    }

	    strcpy(args->parse_file.filename,str);
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

	struct argp argp = { build_options(), parse_opt, args_doc, doc };


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
		if (xlat_is_siit()) {
			log_err("SIIT doesn't have pool4.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return pool4_display();
		case OP_COUNT:
			return pool4_count();
		case OP_ADD:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be added (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool4_add(args.db.pool4.mark,
					&args.db.pool4.prefix,
					&args.db.pool4.ports,
					args.db.pool4.force);
		case OP_REMOVE:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be removed (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool4_rm(args.db.pool4.mark,
					&args.db.pool4.prefix,
					&args.db.pool4.ports, args.db.quick);
		case OP_FLUSH:
			return pool4_flush(args.db.quick);
		default:
			log_err("Unknown operation for IPv4 pool mode: %u.", args.op);
			return -EINVAL;
		}
		break;

	case MODE_BIB:
		if (xlat_is_siit()) {
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
		if (xlat_is_siit()) {
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
		if (xlat_is_nat64()) {
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

	case MODE_RFC6791:
	case MODE_BLACKLIST:
		if (xlat_is_nat64()) {
			log_err("blacklist/RFC6791 don't apply to Stateful NAT64.");
			return -EINVAL;
		}

		switch (args.op) {
		case OP_DISPLAY:
			return pool_display(args.mode);
		case OP_COUNT:
			return pool_count(args.mode);
		case OP_ADD:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be added (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool_add(args.mode, &args.db.pool4.prefix);
		case OP_REMOVE:
			if (!args.db.pool4.prefix_set) {
				log_err("Please enter the address or prefix to be removed (%s).", PREFIX4_FORMAT);
				return -EINVAL;
			}
			return pool_rm(args.mode, &args.db.pool4.prefix);
		case OP_FLUSH:
			return pool_flush(args.mode);
		default:
			log_err("Unknown operation for blacklist or rfc6791 mode: %u.", args.op);
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
		break;

	case MODE_PARSE_FILE:

		return parse_file(args.parse_file.filename);

		break;
	}

	log_err("Unknown configuration mode: %u", args.mode);
	return -EINVAL;
}


int main(int argc, char **argv)
{

	return -main_wrapped(argc, argv);
	return 0;
}
