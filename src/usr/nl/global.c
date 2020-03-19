#include "usr/nl/global.h"

#include <errno.h>
#include <stddef.h>
#include <netlink/msg.h>

#include "common/constants.h"
#include "usr/util/str_utils.h"
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"
#include "usr/nl/json.h"

typedef void (*joolnl_global_print_fn)(void *, bool);
typedef struct jool_result (*joolnl_global_msg2raw_fn)(
	struct nlattr *, void *data
);
typedef struct jool_result (*joolnl_global_str2msg_fn)(
	struct nl_msg *, enum joolnl_attr_global, char const *
);
typedef struct jool_result (*joolnl_global_json2msg_fn)(
	struct nl_msg *, struct joolnl_global_meta const *, cJSON *
);

struct joolnl_global_type {
	char const *name;
	joolnl_global_print_fn print;
	joolnl_global_msg2raw_fn msg2raw;
	joolnl_global_str2msg_fn str2msg;
	joolnl_global_json2msg_fn json2msg;
	char const *candidates; /* Same as in struct wargp_type. */
};

struct joolnl_global_meta {
	enum joolnl_attr_global id;
	char const *name;
	struct joolnl_global_type const *type;
	char const *doc;
	size_t offset;
	xlator_type xt;
	joolnl_global_print_fn print; /* Overrides type->print. */
	char const *candidates; /* Overrides type->candidates. */
};

static void print_bool(void *value, bool csv)
{
	bool bvalue = *((bool *)value);
	if (csv)
		printf("%s", bvalue ? "TRUE" : "FALSE");
	else
		printf("%s", bvalue ? "true" : "false");
}

static void print_u8(void *value, bool csv)
{
	__u8 *uvalue = value;
	printf("%u", *uvalue);
}

static void print_u32(void *value, bool csv)
{
	__u32 *uvalue = value;
	printf("%u", *uvalue);
}

static void print_timeout(void *value, bool csv)
{
	__u32 *uvalue = value;
	char string[TIMEOUT_BUFLEN];

	timeout2str(*uvalue, string);
	printf("%s", string);

	if (!csv)
		printf(" (HH:MM:SS)");
}

static void print_plateaus(void *value, bool csv)
{
	struct mtu_plateaus *plateaus = value;
	unsigned int i;

	if (csv)
		printf("\"");

	for (i = 0; i < plateaus->count; i++) {
		printf("%u", plateaus->values[i]);
		if (i != plateaus->count - 1)
			printf(",");
	}

	if (csv)
		printf("\"");
}

static void print_prefix(int af, const void *addr, __u8 len, bool set, bool csv)
{
	const char *str;
	char buffer[INET6_ADDRSTRLEN];

	if (!set) {
		printf("%s", csv ? "" : "(unset)");
		return;
	}

	str = inet_ntop(af, addr, buffer, sizeof(buffer));
	if (str)
		printf("%s/%u", str, len);
	else
		perror("inet_ntop");
}

static void print_prefix6(void *value, bool csv)
{
	struct config_prefix6 *prefix = value;
	print_prefix(AF_INET6, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set, csv);
}

static void print_prefix4(void *value, bool csv)
{
	struct config_prefix4 *prefix = value;
	print_prefix(AF_INET, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set, csv);
}

static void print_hairpin_mode(void *value, bool csv)
{
	switch (*((__u8 *)value)) {
	case EHM_OFF:
		printf("off");
		return;
	case EHM_SIMPLE:
		printf("simple");
		return;
	case EHM_INTRINSIC:
		printf("intrinsic");
		return;
	}

	printf("unknown");
}

static void print_fargs(void *value, bool csv)
{
	__u8 uvalue = *((__u8 *)value);
	int i;

	printf("%u", uvalue);
	if (csv)
		return;

	printf(" (0b");
	for (i = 3; i >= 0; i--)
		printf("%u", (uvalue >> i) & 0x1);
	printf("): ");

	printf("SrcAddr:%u ", (uvalue >> 3) & 1);
	printf("SrcPort:%u ", (uvalue >> 2) & 1);
	printf("DstAddr:%u ", (uvalue >> 1) & 1);
	printf("DstPort:%u",  (uvalue >> 0) & 1);
}

static struct jool_result msg2raw_bool(struct nlattr *attr, void *out)
{
	*((bool *)out) = nla_get_u8(attr);
	return result_success();
}

static struct jool_result msg2raw_u8(struct nlattr *attr, void *out)
{
	*((__u8 *)out) = nla_get_u8(attr);
	return result_success();
}

static struct jool_result msg2raw_u32(struct nlattr *attr, void *out)
{
	*((__u32 *)out) = nla_get_u32(attr);
	return result_success();
}

static struct jool_result msg2raw_plateaus(struct nlattr *attr, void *out)
{
	return nla_get_plateaus(attr, out);
}

static struct jool_result msg2raw_prefix6(struct nlattr *attr, void *_out)
{
	struct config_prefix6 *out = _out;

	if (nla_len(attr) == 0) {
		out->set = false;
		return result_success();
	}

	out->set = true;
	return nla_get_prefix6(attr, &out->prefix);
}

static struct jool_result msg2raw_prefix4(struct nlattr *attr, void *_out)
{
	struct config_prefix4 *out = _out;

	if (nla_len(attr) == 0) {
		out->set = false;
		return result_success();
	}

	out->set = true;
	return nla_get_prefix4(attr, &out->prefix);
}

static struct jool_result str2msg_bool(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	bool value;
	struct jool_result result;

	result = str_to_bool(string, &value);
	if (result.error)
		return result;

	return (nla_put_u8(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_u8(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	__u8 value;
	struct jool_result result;

	result = str_to_u8(string, &value, MAX_U8);
	if (result.error)
		return result;

	return (nla_put_u8(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_u32(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	__u32 value;
	struct jool_result result;

	result = str_to_u32(string, &value);
	if (result.error)
		return result;

	return (nla_put_u32(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_timeout(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	__u32 value;
	struct jool_result result;

	result = str_to_timeout(string, &value);
	if (result.error)
		return result;

	return (nla_put_u32(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_plateaus(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	struct mtu_plateaus plateaus;
	struct jool_result result;

	result = str_to_plateaus_array(string, &plateaus);
	if (result.error)
		return result;

	return (nla_put_plateaus(msg, id, &plateaus) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_prefix6(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	struct ipv6_prefix prefix, *prefix_ptr;
	struct jool_result result;

	prefix_ptr = NULL;
	if (strcmp(string, "null") != 0) {
		result = str_to_prefix6(string, &prefix);
		if (result.error)
			return result;
		prefix_ptr = &prefix;
	}

	return (nla_put_prefix6(msg, id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_prefix4(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	struct ipv4_prefix prefix, *prefix_ptr;
	struct jool_result result;

	prefix_ptr = NULL;
	if (strcmp(string, "null") != 0) {
		result = str_to_prefix4(string, &prefix);
		if (result.error)
			return result;
		prefix_ptr = &prefix;
	}

	return (nla_put_prefix4(msg, id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2msg_hairpin_mode(struct nl_msg *msg,
		enum joolnl_attr_global id, char const *string)
{
	__u8 mode;

	if (strcmp(string, "off") == 0)
		mode = EHM_OFF;
	else if (strcmp(string, "simple") == 0)
		mode = EHM_SIMPLE;
	else if (strcmp(string, "intrinsic") == 0)
		mode = EHM_INTRINSIC;
	else return result_from_error(
		-EINVAL,
		"'%s' cannot be parsed as a hairpinning mode.\n"
		"Available options: off, simple, intrinsic", string
	);

	return (nla_put_u8(msg, id, mode) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result json2msg_bool(struct nl_msg *msg,
		struct joolnl_global_meta const *meta, cJSON *json)
{
	switch (json->type) {
	case cJSON_True:
		if (nla_put_u8(msg, meta->id, true) < 0)
			return joolnl_err_msgsize();
		return result_success();

	case cJSON_False:
		if (nla_put_u8(msg, meta->id, false) < 0)
			return joolnl_err_msgsize();
		return result_success();
	}

	return type_mismatch(json->string, json, "boolean");
}

static struct jool_result json2msg_u8(struct nl_msg *msg,
		struct joolnl_global_meta const *meta, cJSON *json)
{
	struct jool_result result;

	result = validate_uint(json->string, json, 0, 255);
	if (result.error)
		return result;
	if (nla_put_u8(msg, meta->id, json->valueuint) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result json2msg_u32(struct nl_msg *msg,
		struct joolnl_global_meta const *meta, cJSON *json)
{
	struct jool_result result;

	result = validate_uint(json->string, json, 0, MAX_U32);
	if (result.error)
		return result;
	if (nla_put_u32(msg, meta->id, json->valueuint) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result json2msg_string(struct nl_msg *msg,
		struct joolnl_global_meta const *meta, cJSON *json)
{
	switch (json->type) {
	case cJSON_String:
		return meta->type->str2msg(msg, meta->id, json->valuestring);
	case cJSON_NULL:
		return meta->type->str2msg(msg, meta->id, "null");
	}

	return type_mismatch(json->string, json, "string");
}

static struct jool_result json2msg_plateaus(struct nl_msg *msg,
		struct joolnl_global_meta const *meta, cJSON *json)
{
	struct nlattr *root;
	struct jool_result result;

	if (json->type != cJSON_Array)
		return type_mismatch(json->string, json, "plateaus array");
	/* TODO test zero plateaus */

	root = nla_nest_start(msg, JNLAG_PLATEAUS);
	if (!root)
		return joolnl_err_msgsize();

	for (json = json->child; json; json = json->next) {
		result = validate_uint(meta->name, json, 0, MAX_U16);
		if (result.error)
			return result;

		if (nla_put_u16(msg, JNLAL_ENTRY, json->valueuint) < 0)
			return joolnl_err_msgsize();
	}

	nla_nest_end(msg, root);
	return result_success();
}

static struct joolnl_global_type gt_bool = {
	.name = "Boolean",
	.print = print_bool,
	.msg2raw = msg2raw_bool,
	.str2msg = str2msg_bool,
	.json2msg = json2msg_bool,
	.candidates = "true false",
};

static struct joolnl_global_type gt_uint8 = {
	.name = "8-bit unsigned integer",
	.print = print_u8,
	.msg2raw = msg2raw_u8,
	.str2msg = str2msg_u8,
	.json2msg = json2msg_u8,
};

static struct joolnl_global_type gt_uint32 = {
	.name = "32-bit unsigned integer",
	.print = print_u32,
	.str2msg = str2msg_u32,
	.msg2raw = msg2raw_u32,
	.json2msg = json2msg_u32,
};

static struct joolnl_global_type gt_timeout = {
	.name = "[HH:[MM:]]SS[.mmm]",
	.print = print_timeout,
	.msg2raw = msg2raw_u32,
	.str2msg = str2msg_timeout,
	.json2msg = json2msg_string,
};

static struct joolnl_global_type gt_plateaus = {
	.name = "List of 16-bit unsigned integers separated by commas",
	.print = print_plateaus,
	.msg2raw = msg2raw_plateaus,
	.str2msg = str2msg_plateaus,
	.json2msg = json2msg_plateaus,
};

static struct joolnl_global_type gt_prefix6 = {
	.name = "IPv6 prefix",
	.print = print_prefix6,
	.msg2raw = msg2raw_prefix6,
	.str2msg = str2msg_prefix6,
	.json2msg = json2msg_string,
};

static struct joolnl_global_type gt_prefix4 = {
	.name = "IPv4 prefix",
	.print = print_prefix4,
	.msg2raw = msg2raw_prefix4,
	.str2msg = str2msg_prefix4,
	.json2msg = json2msg_string,
};

static struct joolnl_global_type gt_hairpin_mode = {
	.name = "Hairpinning Mode",
	.print = print_hairpin_mode,
	.msg2raw = msg2raw_u8,
	.str2msg = str2msg_hairpin_mode,
	.json2msg = json2msg_string,
	.candidates = "off simple intrinsic",
};

const struct joolnl_global_meta globals_metadata[] = {
	{
		.id = JNLAG_ENABLED,
		.name = "manually-enabled",
		.type = &gt_bool,
		.doc = "Resumes or pauses the instance's translation.",
		.offset = offsetof(struct globals, enabled),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_POOL6,
		.name = "pool6",
		.type = &gt_prefix6,
		.doc = "The IPv6 Address Pool prefix.",
		.offset = offsetof(struct globals, pool6),
		.xt = XT_ANY,
		.candidates = WELL_KNOWN_PREFIX,
	}, {
		.id = JNLAG_RESET_TC,
		.name = "zeroize-traffic-class",
		.type = &gt_bool,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
		.offset = offsetof(struct globals, reset_traffic_class),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_RESET_TOS,
		.name = "override-tos",
		.type = &gt_bool,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
		.offset = offsetof(struct globals, reset_tos),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_TOS,
		.name = "tos",
		.type = &gt_uint8,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
		.offset = offsetof(struct globals, new_tos),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_PLATEAUS,
		.name = "mtu-plateaus",
		.type = &gt_plateaus,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
		.offset = offsetof(struct globals, plateaus),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_COMPUTE_CSUM_ZERO,
		.name = "amend-udp-checksum-zero",
		.type = &gt_bool,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.",
		.offset = offsetof(struct globals, siit.compute_udp_csum_zero),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_HAIRPIN_MODE,
		.name = "eam-hairpin-mode",
		.type = &gt_hairpin_mode,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.offset = offsetof(struct globals, siit.eam_hairpin_mode),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_RANDOMIZE_ERROR_ADDR,
		.name = "randomize-rfc6791-addresses",
		.type = &gt_bool,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.",
		.offset = offsetof(struct globals, siit.randomize_error_addresses),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_POOL6791V6,
		.name = "rfc6791v6-prefix",
		.type = &gt_prefix6,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.offset = offsetof(struct globals, siit.rfc6791_prefix6),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_POOL6791V4,
		.name = "rfc6791v4-prefix",
		.type = &gt_prefix4,
		.doc = "IPv4 prefix to generate RFC6791 addresses from.",
		.offset = offsetof(struct globals, siit.rfc6791_prefix4),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_DROP_BY_ADDR,
		.name = "address-dependent-filtering",
		.type = &gt_bool,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
		.offset = offsetof(struct globals, nat64.bib.drop_by_addr),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_DROP_ICMP6_INFO,
		.name = "drop-icmpv6-info",
		.type = &gt_bool,
		.doc = "Filter ICMPv6 Informational packets?",
		.offset = offsetof(struct globals, nat64.drop_icmp6_info),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_DROP_EXTERNAL_TCP,
		.name = "drop-externally-initiated-tcp",
		.type = &gt_bool,
		.doc = "Drop externally initiated TCP connections?",
		.offset = offsetof(struct globals, nat64.bib.drop_external_tcp),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TTL_UDP,
		.name = "udp-timeout",
		.type = &gt_timeout,
		.doc = "Set the UDP session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct globals, nat64.bib.ttl.udp),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TTL_ICMP,
		.name = "icmp-timeout",
		.type = &gt_timeout,
		.doc = "Set the timeout for ICMP sessions (HH:MM:SS.mmm).",
		.offset = offsetof(struct globals, nat64.bib.ttl.icmp),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TTL_TCP_EST,
		.name = "tcp-est-timeout",
		.type = &gt_timeout,
		.doc = "Set the TCP established session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct globals, nat64.bib.ttl.tcp_est),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TTL_TCP_TRANS,
		.name = "tcp-trans-timeout",
		.type = &gt_timeout,
		.doc = "Set the TCP transitory session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct globals, nat64.bib.ttl.tcp_trans),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_MAX_STORED_PKTS,
		.name = "maximum-simultaneous-opens",
		.type = &gt_uint32,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.",
		.offset = offsetof(struct globals, nat64.bib.max_stored_pkts),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_SRC_ICMP6_BETTER,
		.name = "source-icmpv6-errors-better",
		.type = &gt_bool,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?",
		.offset = offsetof(struct globals, nat64.src_icmp6errs_better),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_F_ARGS,
		.name = "f-args",
		.type = &gt_uint8,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.",
		.offset = offsetof(struct globals, nat64.f_args),
		.xt = XT_NAT64,
		.print = print_fargs,
	}, {
		.id = JNLAG_HANDLE_RST,
		.name = "handle-rst-during-fin-rcv",
		.type = &gt_bool,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
		.offset = offsetof(struct globals, nat64.handle_rst_during_fin_rcv),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_BIB_LOGGING,
		.name = "logging-bib",
		.type = &gt_bool,
		.doc = "Log BIBs as they are created and destroyed?",
		.offset = offsetof(struct globals, nat64.bib.bib_logging),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_SESSION_LOGGING,
		.name = "logging-session",
		.type = &gt_bool,
		.doc = "Log sessions as they are created and destroyed?",
		.offset = offsetof(struct globals, nat64.bib.session_logging),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TRACE,
		.name = "trace",
		.type = &gt_bool,
		.doc = "Log basic packet fields as they are received?",
		.offset = offsetof(struct globals, trace),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_JOOLD_ENABLED,
		.name = "ss-enabled",
		.type = &gt_bool,
		.doc = "Enable Session Synchronization?",
		.offset = offsetof(struct globals, nat64.joold.enabled),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_FLUSH_ASAP,
		.name = "ss-flush-asap",
		.type = &gt_bool,
		.doc = "Try to synchronize sessions as soon as possible?",
		.offset = offsetof(struct globals, nat64.joold.flush_asap),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_FLUSH_DEADLINE,
		.name = "ss-flush-deadline",
		.type = &gt_uint32,
		.doc = "Inactive milliseconds after which to force a session sync.",
		.offset = offsetof(struct globals, nat64.joold.flush_deadline),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_CAPACITY,
		.name = "ss-capacity",
		.type = &gt_uint32,
		.doc = "Maximim number of queuable entries.",
		.offset = offsetof(struct globals, nat64.joold.capacity),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_MAX_PAYLOAD,
		.name = "ss-max-payload",
		.type = &gt_uint32,
		.doc = "Maximum amount of bytes joold should send per packet.",
		.offset = offsetof(struct globals, nat64.joold.max_payload),
		.xt = XT_NAT64,
	},
};

static const unsigned int globals_metadata_len = sizeof(globals_metadata)
		/ sizeof(globals_metadata[0]);

static struct jool_result handle_query_response(struct nl_msg *msg,
		xlator_type xt, struct nla_policy *policy, struct globals *out)
{
	struct nlattr *attrs[JNLAG_COUNT];
	struct joolnl_global_meta const *meta;
	struct jool_result result;

	result = jnla_parse_msg(msg, attrs, JNLAG_MAX, policy, true);
	if (result.error)
		return result;

	joolnl_global_foreach(meta) {
		if (!(meta->xt & xt))
			continue;
		if (!attrs[meta->id]) {
			return result_from_error(
				-EINVAL,
				"Invalid kernel response: Missing attribute '%s'.",
				meta->name
			);
		}

		result = meta->type->msg2raw(attrs[meta->id],
				((unsigned char *)out) + meta->offset);
		if (result.error)
			return result;
	}

	return result_success();
}

static struct jool_result handle_query_response_siit(struct nl_msg *msg,
		void *args)
{
	return handle_query_response(msg, XT_SIIT, siit_globals_policy, args);
}

static struct jool_result handle_query_response_nat64(struct nl_msg *msg,
		void *args)
{
	return handle_query_response(msg, XT_NAT64, nat64_globals_policy, args);
}

struct jool_result joolnl_global_query(struct joolnl_socket *sk,
		char const *iname, struct globals *out)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JNLOP_GLOBAL_FOREACH, 0, &msg);
	if (result.error)
		return result;

	switch (sk->xt) {
	case XT_SIIT:
		return joolnl_request(sk, msg, handle_query_response_siit, out);
	case XT_NAT64:
		return joolnl_request(sk, msg, handle_query_response_nat64, out);
	}

	return result_from_error(-EINVAL, "Unknown translator type: %u", sk->xt);
}

struct jool_result joolnl_global_update(struct joolnl_socket *sk,
		char const *iname, struct joolnl_global_meta const *meta,
		char const *value, bool force)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JNLOP_GLOBAL_UPDATE,
			force ? JOOLNLHDR_FLAGS_FORCE : 0, &msg);
	if (result.error)
		return result;

	root = nla_nest_start(msg, JNLAR_GLOBALS);
	if (!root)
		return joolnl_err_msgsize();

	result = meta->type->str2msg(msg, meta->id, value);
	if (result.error) {
		nlmsg_free(msg);
		return result;
	}

	nla_nest_end(msg, root);
	return joolnl_request(sk, msg, NULL, NULL);
}

struct jool_result joolnl_global_packetize_json(struct nl_msg *msg,
	struct joolnl_global_meta const *meta, cJSON *json)
{
	return meta->type->json2msg(msg, meta, json);
}

void joolnl_global_print(struct joolnl_global_meta const *meta,
		struct globals *config, bool csv)
{
	joolnl_global_print_fn print;
	print = meta->print ? meta->print : meta->type->print;
	print(((unsigned char *)config) + meta->offset, csv);
}

struct joolnl_global_meta const *joolnl_global_meta_first(void)
{
	return globals_metadata;
}

struct joolnl_global_meta const *joolnl_global_meta_next(
		struct joolnl_global_meta const *meta)
{
	return meta + 1;
}

struct joolnl_global_meta const *joolnl_global_meta_last(void)
{

	return &globals_metadata[globals_metadata_len - 1];
}

unsigned int joolnl_global_meta_count(void)
{
	return globals_metadata_len;
}

char const *joolnl_global_meta_name(struct joolnl_global_meta const *meta)
{
	return meta->name;
}

xlator_type joolnl_global_meta_xt(struct joolnl_global_meta const *meta)
{
	return meta->xt;
}

char const *joolnl_global_meta_values(struct joolnl_global_meta const *meta)
{
	return meta->candidates ? meta->candidates : meta->type->candidates;
}
