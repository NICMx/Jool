/**
 * @file
 * Main for the `jool_siit` and `jool` userspace applications.
 * Parses parameters from the user and hands the real work to the other .c's.
 */

#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>

#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/common/xlat.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/instance.h"
#include "nat64/usr/file.h"
#include "nat64/usr/joold.h"
#include "nat64/usr/json.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/pool.h"
#include "nat64/usr/pool6.h"
#include "nat64/usr/pool4.h"
#include "nat64/usr/bib.h"
#include "nat64/usr/session.h"
#include "nat64/usr/eam.h"
#include "nat64/usr/global.h"
#include "nat64/usr/log_time.h"
#include "nat64/usr/argp/options.h"



const char *argp_program_version = JOOL_VERSION_STR;
const char *argp_program_bug_address = "jool@nic.mx";

/**
 * The program arguments received from the user,
 * formatted and ready to be read in any order.
 */
struct arguments {
	enum config_mode mode;
	enum config_operation op;

	struct {
		bool quick;
		bool force;
		bool tcp, udp, icmp;
		bool numeric;

		struct ipv6_prefix prefix6;
		bool prefix6_set;

		struct ipv4_prefix prefix4;
		bool prefix4_set;

		struct {
			__u32 mark;
			struct port_range ports;
			bool force;
		} pool4;

		struct {
			struct ipv6_transport_addr addr6;
			bool addr6_set;
			struct ipv4_transport_addr addr4;
			bool addr4_set;
		} bib;
	} db;

	struct {
		__u16 type;
		size_t size;
		void *data;
	} global;

	char *json_filename;

	bool csv_format;
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
	log_err("Illegal arguments combination. See the manpage for grammar.");
	return -EINVAL;
}

static int set_global_arg(struct arguments *args, __u16 type, size_t size,
		void *value)
{
	int error = update_state(args, MODE_GLOBAL, OP_UPDATE);
	if (error)
		return error;

	if (args->global.data) {
		log_err("You can only edit one global config value at a time.");
		return -EINVAL;
	}

	args->global.type = type;
	args->global.size = size;
	args->global.data = NULL;

	if (size != 0) {
		args->global.data = malloc(size);
		if (!args->global.data)
			return -ENOMEM;

		memcpy(args->global.data, value, size);
	}


	return 0;
}

static int set_global_bool(struct arguments *args, __u16 type, char *value)
{
	__u8 tmp;
	int error;

	error = str_to_bool(value, &tmp);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

static int set_global_u8(struct arguments *args, __u16 type, char *value,
		__u8 min, __u8 max)
{
	__u8 tmp;
	int error;

	error = str_to_u8(value, &tmp, min, max);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

static int set_global_u16(struct arguments *args, __u16 type, char *value,
		__u16 min, __u16 max)
{
	__u16 tmp;
	int error;

	error = str_to_u16(value, &tmp, min, max);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

static int set_global_u32(struct arguments *args, __u16 type, char *value,
		__u32 min, __u32 max)
{
	__u32 tmp;
	int error;

	error = str_to_u32(value, &tmp, min, max);
	if (error)
		return error;

	return set_global_arg(args, type, sizeof(tmp), &tmp);
}

static int set_global_u64(struct arguments *args, __u16 type, char *value,
		__u64 min, __u64 max,
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

static int set_global_rfc6791_prefix(struct arguments *args, __u16 type, char *value)
{
	int error;

	struct ipv6_prefix tmp;

	if (strcmp(value, "null") != 0) {
		error = str_to_prefix6(value, &tmp);
		if (error)
			return error;

		return set_global_arg(args, type, sizeof(tmp), &tmp);
	}

	return set_global_arg(args, type, 0, 0);
}

static int set_global_u16_array(struct arguments *args, __u16 type, char *value)
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

	error = update_state(args, MODE_POOL4 | MODE_BLACKLIST | MODE_RFC6791
			| MODE_EAMT, OP_ADD | OP_REMOVE);
	if (error)
		return error;

	if (args->db.prefix4_set) {
		log_err("Only one IPv4 prefix can be added/removed at a time.");
		return -EINVAL;
	}

	args->db.prefix4_set = true;
	return str_to_prefix4(str, &args->db.prefix4);
}

static int set_ipv6_prefix(struct arguments *args, char *str)
{
	int error;

	error = update_state(args, MODE_POOL6 | MODE_EAMT, OP_ADD | OP_UPDATE
			| OP_REMOVE);
	if (error)
		return error;

	if (args->db.prefix6_set) {
		log_err("Only one IPv6 prefix can be added/removed at a time.");
		return -EINVAL;
	}

	args->db.prefix6_set = true;
	return str_to_prefix6(str, &args->db.prefix6);
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

	if (args->db.bib.addr6_set) {
		log_err("You entered more than one IPv6 transport address.");
		log_err("Only one BIB entry can be added/removed at a time.");
		return -EINVAL;
	}

	args->db.bib.addr6_set = true;
	return str_to_addr6_port(str, &args->db.bib.addr6);
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

	if (args->db.bib.addr4_set) {
		log_err("You entered more than one IPv4 transport address.");
		log_err("Only one BIB entry can be added/removed at a time.");
		return -EINVAL;
	}

	args->db.bib.addr4_set = true;
	return str_to_addr4_port(str, &args->db.bib.addr4);
}

static int set_port_range(struct arguments *args, char *str)
{
	int error;

	if (xlat_is_siit()) {
		log_err("You seem to have entered a port range. SIIT doesn't need them...");
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
	int error;

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
	case ARGP_JOOLD:
		error = update_state(args, MODE_JOOLD, JOOLD_OPS);
		break;

	case ARGP_LOGTIME:
		error = update_state(args, MODE_LOGTIME, LOGTIME_OPS);
		break;
	case ARGP_INSTANCE:
		error = update_state(args, MODE_INSTANCE, INSTANCE_OPS);
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
	case ARGP_ADVERTISE:
		error = update_state(args, MODE_JOOLD, OP_ADVERTISE);
		break;
	case ARGP_TEST:
		error = update_state(args, MODE_JOOLD, OP_TEST);
		break;

	case ARGP_UDP:
		error = update_state(args, MODE_POOL4 | MODE_BIB | MODE_SESSION,
				POOL4_OPS | BIB_OPS | SESSION_OPS);
		args->db.udp = true;
		break;
	case ARGP_TCP:
		error = update_state(args, MODE_POOL4 | MODE_BIB | MODE_SESSION,
				POOL4_OPS | BIB_OPS | SESSION_OPS);
		args->db.tcp = true;
		break;
	case ARGP_ICMP:
		error = update_state(args, MODE_POOL4 | MODE_BIB | MODE_SESSION,
				POOL4_OPS | BIB_OPS | SESSION_OPS);
		args->db.icmp = true;
		break;
	case ARGP_NUMERIC_HOSTNAME:
		error = update_state(args, MODE_BIB | MODE_SESSION, OP_DISPLAY);
		args->db.numeric = true;
		break;
	case ARGP_CSV:
		error = update_state(args, POOL_MODES | TABLE_MODES
				| MODE_GLOBAL, OP_DISPLAY);
		args->csv_format = true;
		break;

	case ARGP_QUICK:
		error = update_state(args, MODE_POOL4, OP_REMOVE | OP_FLUSH);
		args->db.quick = true;
		break;
	case ARGP_MARK:
		error = update_state(args, MODE_POOL4, OP_ADD | OP_REMOVE);
		if (!error)
			error = str_to_u32(str, &args->db.pool4.mark, 0, MAX_U32);
		break;
	case ARGP_FORCE:
		error = update_state(args, ANY_MODE, ANY_OP);
		args->db.force = true;
		break;

	case ARGP_ENABLE_TRANSLATION:
	case ARGP_DISABLE_TRANSLATION:
		error = set_global_bool(args, key, "true");
		break;
	case ARGP_RESET_TCLASS:
	case ARGP_RESET_TOS:
	case ARGP_COMPUTE_CSUM_ZERO:
	case ARGP_RANDOMIZE_RFC6791:
	case ARGP_DROP_ADDR:
	case ARGP_DROP_INFO:
	case ARGP_DROP_TCP:
	case ARGP_SRC_ICMP6ERRS_BETTER:
	case ARGP_BIB_LOGGING:
	case ARGP_SESSION_LOGGING:
	case ARGP_SS_ENABLED:
	case ARGP_SS_FLUSH_ASAP:
		error = set_global_bool(args, key, str);
		break;
	case ARGP_F_ARGS:
		error = set_global_u8(args, key, str, 0, 0xF);
		break;
	case ARGP_HANDLE_RST_DURING_FIN_RCV:
		error = set_global_bool(args, HANDLE_RST_DURING_FIN_RCV, str);
		break;
	case ARGP_NEW_TOS:
		error = set_global_u8(args, key, str, 0, MAX_U8);
		break;
	case ARGP_PLATEAUS:
		error = set_global_u16_array(args, key, str);
		break;
	case ARGP_EAM_HAIRPIN_MODE:
		error = set_global_u8(args, key, str, 0, EAM_HAIRPIN_MODE_COUNT - 1);
		break;
	case ARGP_UDP_TO:
		error = set_global_u64(args, key, str, UDP_MIN, MAX_U32/1000, 1000);
		break;
	case ARGP_ICMP_TO:
		error = set_global_u64(args, key, str, 0, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TO:
		error = set_global_u64(args, key, str, TCP_EST, MAX_U32/1000, 1000);
		break;
	case ARGP_TCP_TRANS_TO:
		error = set_global_u64(args, key, str, TCP_TRANS, MAX_U32/1000, 1000);
		break;
	case ARGP_FRAG_TO:
		error = set_global_u64(args, key, str, FRAGMENT_MIN, MAX_U32/1000, 1000);
		break;
	case ARGP_STORED_PKTS:
		error = set_global_u32(args, key, str, 0, MAX_U32);
		break;
	case ARGP_SS_FLUSH_DEADLINE:
		error = set_global_u64(args, key, str, 0, MAX_U32, 1);
		break;
	case ARGP_SS_CAPACITY:
		error = set_global_u32(args, key, str, 0, MAX_U32);
		break;
	case ARGP_SS_MAX_PAYLOAD:
		error = set_global_u16(args, key, str, 0, JOOLD_MAX_PAYLOAD);
		break;
	case ARGP_RFC6791V6_PREFIX:
		error = set_global_rfc6791_prefix(args, key, str);
		break;
	case ARGP_PREFIX:
		error = set_ipv6_prefix(args, str);
		break;
	case ARGP_ADDRESS:
		error = set_ipv4_prefix(args, str);
		break;
	case ARGP_BIB_IPV6:
		error = set_bib6(args, str);
		break;
	case ARGP_BIB_IPV4:
		error = set_bib4(args, str);
		break;

	case ARGP_KEY_ARG:
		error = set_ip_args(args, str);
		break;
	case ARGP_PARSE_FILE:
		error = update_state(args, MODE_PARSE_FILE, OP_UPDATE);

		args->json_filename = malloc(sizeof(char) * (strlen(str) + 1));
		if (!args->json_filename) {
			error = -ENOMEM;
			log_err("Unable to allocate memory!.");
			break;
		}

		strcpy(args->json_filename, str);
		break;

	default:
		error = ARGP_ERR_UNKNOWN;
	}

	return error;
}

/**
 * Third ARGP field.
 * A description of the non-option command-line arguments we accept.
 */
static char args_doc[] = "{address specification}";

/*
 * Fourth ARGP field.
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
 * Uses argp.h to read the parameters from the user, validates them,
 * translates them to a structure and returns the result.
 */
static int parse_args(int argc, char **argv, struct arguments *result)
{
	int error;
	struct argp_option *options = build_opts();
	struct argp argp = { options, parse_opt, args_doc, doc };


	memset(result, 0, sizeof(*result));
	result->mode = ANY_MODE;
	result->op = ANY_OP;
	result->db.pool4.ports.min = 0;
	result->db.pool4.ports.max = 65535U;

	error = argp_parse(&argp, argc, argv, 0, NULL, result);
	free(options);
	if (error)
		return error;

	result->mode = zeroize_upper_bits(result->mode);
	result->op = zeroize_upper_bits(result->op);

	if (!result->db.tcp && !result->db.udp && !result->db.icmp) {
		result->db.tcp = true;
		result->db.udp = true;
		result->db.icmp = true;
	}

	return 0;
}

static void destroy_args(struct arguments *args)
{
	free(args->json_filename);
	free(args->global.data);
}

static int unknown_op(char *mode, enum config_operation op)
{
	log_err("Unknown operation for %s mode: %u.", mode, op);
	return -EINVAL;
}

static int handle_pool6(struct arguments *args)
{
	switch (args->op) {
	case OP_DISPLAY:
		return pool6_display(args->csv_format);

	case OP_ADD:
	case OP_UPDATE:
		if (!args->db.prefix6_set) {
			log_err("The IPv6 prefix is mandatory.");
			return -EINVAL;
		}
		return pool6_add(&args->db.prefix6, args->db.force);

	case OP_REMOVE:
		if (!args->db.prefix6_set) {
			log_err("The IPv6 prefix is mandatory.");
			return -EINVAL;
		}
		return pool6_remove(&args->db.prefix6);

	case OP_COUNT:
		return pool6_count();
	case OP_FLUSH:
		return pool6_flush();
	default:
		return unknown_op("IPv6 pool", args->op);
	}
}

static int handle_pool4(struct arguments *args)
{
	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return -EINVAL;
	}

	switch (args->op) {
	case OP_DISPLAY:
		return pool4_display(args->csv_format);
	case OP_COUNT:
		return pool4_count();

	case OP_ADD:
		if (!args->db.prefix4_set) {
			log_err("The address/prefix argument is mandatory.");
			return -EINVAL;
		}
		return pool4_add(args->db.pool4.mark,
				args->db.tcp, args->db.udp, args->db.icmp,
				&args->db.prefix4, &args->db.pool4.ports,
				args->db.force);

	case OP_REMOVE:
		if (!args->db.prefix4_set) {
			log_err("The address/prefix argument is mandatory.");
			return -EINVAL;
		}
		return pool4_rm(args->db.pool4.mark,
				args->db.tcp, args->db.udp, args->db.icmp,
				&args->db.prefix4, &args->db.pool4.ports,
				args->db.quick);

	case OP_FLUSH:
		return pool4_flush(args->db.quick);
	default:
		return unknown_op("IPv4 pool", args->op);
	}
}

static int handle_bib(struct arguments *args)
{
	struct ipv6_transport_addr *addr6;
	struct ipv4_transport_addr *addr4;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have BIBs.");
		return -EINVAL;
	}

	addr6 = args->db.bib.addr6_set ? &args->db.bib.addr6 : NULL;
	addr4 = args->db.bib.addr4_set ? &args->db.bib.addr4 : NULL;

	switch (args->op) {
	case OP_DISPLAY:
		return bib_display(args->db.tcp, args->db.udp, args->db.icmp,
				args->db.numeric, args->csv_format);
	case OP_COUNT:
		return bib_count(args->db.tcp, args->db.udp, args->db.icmp);

	case OP_ADD:
		if (!addr6 || !addr4) {
			log_err("The transport address arguments are mandatory during adds.");
			return -EINVAL;
		}
		return bib_add(args->db.tcp, args->db.udp, args->db.icmp,
				addr6, addr4);

	case OP_REMOVE:
		if (!addr6 && !addr4) {
			log_err("A remove requires an IPv4 and/or v6 transport address.");
			return -EINVAL;
		}
		return bib_remove(args->db.tcp, args->db.udp, args->db.icmp,
				addr6, addr4);

	default:
		return unknown_op("BIB", args->op);
	}
}

static int handle_session(struct arguments *args)
{
	if (xlat_is_siit()) {
		log_err("SIIT doesn't have sessions.");
		return -EINVAL;
	}

	switch (args->op) {
	case OP_DISPLAY:
		return session_display(args->db.tcp, args->db.udp, args->db.icmp,
				args->db.numeric, args->csv_format);
	case OP_COUNT:
		return session_count(args->db.tcp, args->db.udp, args->db.icmp);
	default:
		return unknown_op("session", args->op);
	}
}

static int handle_eamt(struct arguments *args)
{
	struct ipv6_prefix *prefix6;
	struct ipv4_prefix *prefix4;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have EAMTs.");
		return -EINVAL;
	}

	prefix6 = args->db.prefix6_set ? &args->db.prefix6 : NULL;
	prefix4 = args->db.prefix4_set ? &args->db.prefix4 : NULL;

	switch (args->op) {
	case OP_DISPLAY:
		return eam_display(args->csv_format);
	case OP_COUNT:
		return eam_count();

	case OP_ADD:
		if (!prefix6 || !prefix4) {
			log_err("Both EAM prefixes are mandatory during adds.");
			return -EINVAL;
		}
		return eam_add(prefix6, prefix4, args->db.force);

	case OP_REMOVE:
		if (!prefix6 && !prefix4) {
			log_err("A remove requires an IPv4 and/or v6 prefix.");
			return -EINVAL;
		}
		return eam_remove(prefix6, prefix4);

	case OP_FLUSH:
		return eam_flush();
	default:
		return unknown_op("EAMT", args->op);
	}
}

static int handle_addr4_pool(struct arguments *args)
{
	if (xlat_is_nat64()) {
		log_err("blacklist/RFC6791 don't apply to Stateful NAT64.");
		return -EINVAL;
	}

	switch (args->op) {
	case OP_DISPLAY:
		return pool_display(args->mode, args->csv_format);
	case OP_COUNT:
		return pool_count(args->mode);

	case OP_ADD:
		if (!args->db.prefix4_set) {
			log_err("The address/prefix argument is mandatory.");
			return -EINVAL;
		}
		return pool_add(args->mode, &args->db.prefix4, args->db.force);

	case OP_REMOVE:
		if (!args->db.prefix4_set) {
			log_err("The address/prefix argument is mandatory.");
			return -EINVAL;
		}
		return pool_rm(args->mode, &args->db.prefix4);

	case OP_FLUSH:
		return pool_flush(args->mode);
	default:
		return unknown_op("rfc6791", args->op);
	}
}

static int handle_logtime(struct arguments *args)
{
#ifdef BENCHMARK
	switch (args->op) {
	case OP_DISPLAY:
		return logtime_display();
	default:
		log_err("Unknown operation for logtime mode: %u.", args->op);
		break;
	}
#else
	log_err("Benchmark mode was disabled during compilation.");
	return -EINVAL;
#endif
}

static int handle_global(struct arguments *args)
{
	switch (args->op) {
	case OP_DISPLAY:
		return global_display(args->csv_format);
	case OP_UPDATE:
		return global_update(args->global.type, args->global.size,
				args->global.data);
	default:
		return unknown_op("global", args->op);
	}
}
static int handle_joold(struct arguments *args)
{
	switch (args->op) {
	case OP_ADVERTISE:
		return joold_advertise();
	case OP_TEST:
		return joold_test();
	default:
		return unknown_op("joold", args->op);
	}
}
static int handle_instance(struct arguments *args)
{
	switch (args->op) {
	case OP_ADD:
		return instance_add();
	case OP_REMOVE:
		return instance_rm();
	default:
		return unknown_op("instance", args->op);
	}
}

static int main_wrapped(struct arguments *args)
{
	switch (args->mode) {
	case MODE_POOL6:
		return handle_pool6(args);
	case MODE_POOL4:
		return handle_pool4(args);
	case MODE_BIB:
		return handle_bib(args);
	case MODE_SESSION:
		return handle_session(args);
	case MODE_EAMT:
		return handle_eamt(args);
	case MODE_RFC6791:
	case MODE_BLACKLIST:
		return handle_addr4_pool(args);
	case MODE_LOGTIME:
		return handle_logtime(args);
	case MODE_GLOBAL:
		return handle_global(args);
	case MODE_PARSE_FILE:
		return parse_file(args->json_filename);
	case MODE_JOOLD:
		return handle_joold(args);
	case MODE_INSTANCE:
		return handle_instance(args);
	}

	log_err("Unknown configuration mode: %u", args->mode);
	return -EINVAL;
}

int main(int argc, char **argv)
{
	struct arguments args;
	int error;

	error = parse_args(argc, argv, &args);
	if (error)
		return error;

	error = netlink_init();
	if (error) {
		destroy_args(&args);
		return error;
	}

	error = main_wrapped(&args);
	netlink_destroy();
	destroy_args(&args);
	return error;

}
