#include "common/global.h"

#ifdef __KERNEL__
#include "mod/common/log.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/global.h"
#else
#include <stddef.h>
#include <errno.h>
#include "usr/util/str_utils.h"
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"
#include "usr/nl/json.h"
#endif
#include "common/constants.h"

#ifdef __KERNEL__

typedef int (*joolnl_global_raw2nl_fn)(
	struct joolnl_global_meta const *,
	void *,
	struct sk_buff *
);
typedef int (*joolnl_global_nl2raw_fn)(
	struct joolnl_global_meta const *,
	struct nlattr *,
	void *,
	bool,
	struct jnl_state *
);

#else

typedef void (*joolnl_global_print_fn)(void *, bool);

typedef struct jool_result (*joolnl_global_str2nl_fn)(
	enum joolnl_attr_global,
	char const *,
	struct nl_msg *
);
typedef struct jool_result (*joolnl_global_json2nl_fn)(
	struct joolnl_global_meta const *,
	cJSON *,
	struct nl_msg *
);
typedef struct jool_result (*joolnl_global_nl2raw_fn)(
	struct nlattr *,
	void *data
);

#endif

struct joolnl_global_type {
	char const *name;
	char const *candidates; /* Same as in struct wargp_type. */
#ifdef __KERNEL__
	joolnl_global_raw2nl_fn raw2nl;
#else
	joolnl_global_print_fn print;
	joolnl_global_str2nl_fn str2nl;
	joolnl_global_json2nl_fn json2nl;
#endif
	joolnl_global_nl2raw_fn nl2raw;
};

struct joolnl_global_meta {
	enum joolnl_attr_global id;
	char const *name;
	struct joolnl_global_type const *type;
	char const *doc;
	char const *candidates; /* Overrides type->candidates. */
	size_t offset;
	xlator_type xt;
#ifdef __KERNEL__
	joolnl_global_nl2raw_fn nl2raw; /* Overrides type->nl2raw. */
#else
	joolnl_global_print_fn print; /* Overrides type->print. */
#endif
};

#ifdef __KERNEL__

static int raw2nl_bool(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	return nla_put_u8(skb, meta->id, *((bool *)raw));
}

static int raw2nl_u8(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	return nla_put_u8(skb, meta->id, *((__u8 *)raw));
}

static int raw2nl_u32(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	return nla_put_u32(skb, meta->id, *((__u32 *)raw));
}

static int raw2nl_plateaus(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	return jnla_put_plateaus(skb, meta->id, raw);
}

static int raw2nl_prefix6(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	struct config_prefix6 *prefix6 = raw;
	return jnla_put_prefix6(skb, meta->id,
			prefix6->set ? &prefix6->prefix : NULL);
}

static int raw2nl_prefix4(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	struct config_prefix4 *prefix4 = raw;
	return jnla_put_prefix4(skb, meta->id,
			prefix4->set ? &prefix4->prefix : NULL);
}

static int raw2nl_mapping_rule(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb)
{
	return jnla_put_mapping_rule(skb, meta->id, raw);
}

static int nl2raw_bool(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	*((bool *)raw) = nla_get_u8(attr);
	return 0;
}

static int nl2raw_u8(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	*((__u8 *)raw) = nla_get_u8(attr);
	return 0;
}

static int nl2raw_u32(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	*((__u32 *)raw) = nla_get_u32(attr);
	return 0;
}

static int nl2raw_plateaus(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	return jnla_get_plateaus(attr, raw, state);
}

static int validate_prefix6791v4(struct config_prefix4 *prefix, bool force,
		struct jnl_state *state)
{
	int error;

	if (!prefix->set)
		return 0;

	error = prefix4_validate(&prefix->prefix, state);
	if (error)
		return error;

	return prefix4_validate_scope(&prefix->prefix, force, state);
}

static int nl2raw_pool6(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	struct config_prefix6 *prefix = raw;
	int error;

	error = jnla_get_prefix6_optional(attr, meta->name, prefix, state);
	if (error)
		return error;

	return pool6_validate(prefix, force, state);
}

static int nl2raw_prefix6(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	struct config_prefix6 *prefix = raw;
	int error;

	error = jnla_get_prefix6_optional(attr, meta->name, prefix, state);
	if (error)
		return error;

	return prefix->set ? prefix6_validate(&prefix->prefix, state) : 0;
}

static int nl2raw_pool6791v4(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	struct config_prefix4 *prefix = raw;
	int error;

	error = jnla_get_prefix4_optional(attr, meta->name, prefix, state);
	if (error)
		return error;

	return validate_prefix6791v4(prefix, force, state);
}

static int nl2raw_lowest_ipv6_mtu(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u32 lim;

	lim = nla_get_u32(attr);
	if (lim < 1280) {
		return jnls_err(
			state,
			"%s (%u) is too small (min: 1280).",
			meta->name, lim
		);
	}

	*((__u32 *)raw) = lim;
	return 0;
}

static int nl2raw_hairpin_mode(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u8 mode;

	mode = nla_get_u8(attr);
	if (mode != EHM_OFF && mode != EHM_SIMPLE && mode != EHM_INTRINSIC)
		return jnls_err(state, "Unknown hairpinning mode: %u", mode);

	*((__u8 *)raw) = mode;
	return 0;
}

static int nl2raw_maptype(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u8 type;

	type = nla_get_u8(attr);
	if (type != MAPTYPE_BR && type != MAPTYPE_CE)
		return jnls_err(state, "Unknown MAP-T type: %u", type);

	*((__u8 *)raw) = type;
	return 0;
}

static int validate_timeout(const char *what, __u32 timeout, unsigned int min,
		struct jnl_state *state)
{
	if (timeout < min) {
		return jnls_err(state,
				"The '%s' timeout (%u) is too small. (min: %u)",
				what, timeout, min);
	}

	return 0;
}

static int nl2raw_ttl_udp(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u32 ttl;
	int error;

	ttl = nla_get_u32(attr);
	error = validate_timeout(meta->name, ttl, 1000 * UDP_MIN, state);
	if (!error)
		*((__u32 *)raw) = ttl;

	return error;
}

static int nl2raw_ttl_tcp_est(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u32 ttl;
	int error;

	ttl = nla_get_u32(attr);
	error = validate_timeout(meta->name, ttl, 1000 * TCP_EST, state);
	if (!error)
		*((__u32 *)raw) = ttl;

	return error;
}

static int nl2raw_ttl_tcp_trans(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u32 ttl;
	int error;

	ttl = nla_get_u32(attr);
	error = validate_timeout(meta->name, ttl, 1000 * TCP_TRANS, state);
	if (!error)
		*((__u32 *)raw) = ttl;

	return error;
}

static int nl2raw_f_args(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	__u8 f_args;

	f_args = nla_get_u8(attr);
	if (f_args > 0x0Fu) {
		return jnls_err(state, "%s (%u) is out of range. (0-%u)",
				meta->name, f_args, 0x0Fu);
	}

	*((__u8 *)raw) = f_args;
	return 0;
}

static int nl2raw_mapping_rule(struct joolnl_global_meta const *meta,
		struct nlattr *attr, void *raw, bool force,
		struct jnl_state *state)
{
	return jnla_get_mapping_rule(attr, meta->name, raw, state);
}

#else

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

static void __print_prefix(int af, const void *addr, __u8 len)
{
	const char *str;
	char buffer[INET6_ADDRSTRLEN];

	str = inet_ntop(af, addr, buffer, sizeof(buffer));
	if (str)
		printf("%s/%u", str, len);
	else
		perror("inet_ntop");
}

static void print_prefix(int af, const void *addr, __u8 len, bool set, bool csv)
{
	if (!set) {
		printf("%s", csv ? "" : "(unset)");
		return;
	}

	__print_prefix(af, addr, len);
}

/* Remember that @value is a config_prefix6, not an ipv6_prefix. */
static void print_prefix6(void *value, bool csv)
{
	struct config_prefix6 *prefix = value;
	print_prefix(AF_INET6, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set, csv);
}

/* Remember that @value is a config_prefix4, not an ipv4_prefix. */
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

static void print_maptype(void *value, bool csv)
{
	switch (*((__u8 *)value)) {
	case MAPTYPE_BR:
		printf("BR");
		return;
	case MAPTYPE_CE:
		printf("CE");
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

static void __print_prefix6(struct ipv6_prefix *prefix)
{
	__print_prefix(AF_INET6, &prefix->addr, prefix->len);
}

static void __print_prefix4(struct ipv4_prefix *prefix)
{
	__print_prefix(AF_INET, &prefix->addr, prefix->len);
}

static void print_mapping_rule(void *value, bool csv)
{
	struct config_mapping_rule *_rule = value;
	struct mapping_rule *rule;

	if (!_rule->set) {
		printf("%s", csv ? "" : "(unset)");
		return;
	}

	rule = &_rule->rule;
	if (csv) {
		__print_prefix6(&rule->prefix6);
		printf(",");
		__print_prefix4(&rule->prefix4);
		printf(",%u,%u", rule->o, rule->a);
	} else {
		__print_prefix6(&rule->prefix6);
		printf(" ");
		__print_prefix4(&rule->prefix4);
		printf(" %u %u", rule->o, rule->a);
	}
}

static struct jool_result nl2raw_bool(struct nlattr *attr, void *raw)
{
	*((bool *)raw) = nla_get_u8(attr);
	return result_success();
}

static struct jool_result nl2raw_u8(struct nlattr *attr, void *raw)
{
	*((__u8 *)raw) = nla_get_u8(attr);
	return result_success();
}

static struct jool_result nl2raw_u32(struct nlattr *attr, void *raw)
{
	*((__u32 *)raw) = nla_get_u32(attr);
	return result_success();
}

static struct jool_result nl2raw_plateaus(struct nlattr *attr, void *raw)
{
	return nla_get_plateaus(attr, raw);
}

static struct jool_result nl2raw_prefix6(struct nlattr *attr, void *raw)
{
	struct config_prefix6 *prefix = raw;
	struct jool_result result;

	result = nla_get_prefix6(attr, &prefix->prefix);
	switch (result.error) {
	case 0:
		prefix->set = true;
		return result_success();
	case -ENOENT:
		prefix->set = false;
		return result_success();
	}

	return result;
}

static struct jool_result nl2raw_prefix4(struct nlattr *attr, void *raw)
{
	struct config_prefix4 *prefix = raw;
	struct jool_result result;

	result = nla_get_prefix4(attr, &prefix->prefix);
	switch (result.error) {
	case 0:
		prefix->set = true;
		return result_success();
	case -ENOENT:
		prefix->set = false;
		return result_success();
	}

	return result;
}

static struct jool_result nl2raw_mapping_rule(struct nlattr *attr, void *raw)
{
	return nla_get_mapping_rule(attr, raw);
}

static struct jool_result str2nl_bool(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	bool value;
	struct jool_result result;

	result = str_to_bool(str, &value);
	if (result.error)
		return result;

	return (nla_put_u8(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_u8(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	__u8 value;
	struct jool_result result;

	result = str_to_u8(str, &value, MAX_U8);
	if (result.error)
		return result;

	return (nla_put_u8(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_u32(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	__u32 value;
	struct jool_result result;

	result = str_to_u32(str, &value);
	if (result.error)
		return result;

	return (nla_put_u32(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_timeout(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	__u32 value;
	struct jool_result result;

	result = str_to_timeout(str, &value);
	if (result.error)
		return result;

	return (nla_put_u32(msg, id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_plateaus(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	struct mtu_plateaus plateaus;
	struct jool_result result;

	result = str_to_plateaus_array(str, &plateaus);
	if (result.error)
		return result;

	return (nla_put_plateaus(msg, id, &plateaus) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_prefix6(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	struct ipv6_prefix prefix, *prefix_ptr;
	struct jool_result result;

	prefix_ptr = NULL;
	if (strcmp(str, "null") != 0) {
		result = str_to_prefix6(str, &prefix);
		if (result.error)
			return result;
		prefix_ptr = &prefix;
	}

	return (nla_put_prefix6(msg, id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_prefix4(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	struct ipv4_prefix prefix, *prefix_ptr;
	struct jool_result result;

	prefix_ptr = NULL;
	if (strcmp(str, "null") != 0) {
		result = str_to_prefix4(str, &prefix);
		if (result.error)
			return result;
		prefix_ptr = &prefix;
	}

	return (nla_put_prefix4(msg, id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_hairpin_mode(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	__u8 mode;

	if (strcmp(str, "off") == 0)
		mode = EHM_OFF;
	else if (strcmp(str, "simple") == 0)
		mode = EHM_SIMPLE;
	else if (strcmp(str, "intrinsic") == 0)
		mode = EHM_INTRINSIC;
	else return result_from_error(
		-EINVAL,
		"'%s' cannot be parsed as a hairpinning mode.\n"
		"Available options: off, simple, intrinsic", str
	);

	return (nla_put_u8(msg, id, mode) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_maptype(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	__u8 mode;

	if (strcmp(str, "BR") == 0)
		mode = MAPTYPE_BR;
	else if (strcmp(str, "CE") == 0)
		mode = MAPTYPE_CE;
	else return result_from_error(
		-EINVAL,
		"'%s' cannot be parsed as a MAP-T type.\n"
		"Available options: BR, CE", str
	);

	return (nla_put_u8(msg, id, mode) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

static struct jool_result str2nl_mapping_rule(enum joolnl_attr_global id,
		char const *str, struct nl_msg *msg)
{
	char *str_copy, *token, *saveptr;
	unsigned int fields;
	struct mapping_rule rule, *rule_ptr;
	struct jool_result result;

	if (strcmp(str, "null") == 0) {
		rule_ptr = NULL;
		goto end;
	}

	str_copy = strdup(str);
	if (!str_copy)
		return result_from_enomem();

	rule.a = 6u;
	for (
		token = strtok_r(str_copy, " \t", &saveptr), fields = 0;
		token;
		token = strtok_r(NULL, " \t", &saveptr), fields++
	) {
		switch (fields) {
		case 0:
			result = str_to_prefix6(token, &rule.prefix6);
			break;
		case 1:
			result = str_to_prefix4(token, &rule.prefix4);
			break;
		case 2:
			result = str_to_u8(token, &rule.o, 48);
			break;
		case 3:
			result = str_to_u8(token, &rule.a, 16);
			break;
		default:
			return result_from_error(-EINVAL, "Too many arguments. Expected: <IPv6 Prefix> <IPv4 Prefix> <EA-bits length> [<a>]");
		}

		if (result.error)
			return result;
	}

	if (fields < 3)
		return result_from_error(-EINVAL, "Not enough arguments. Expected: <IPv6 Prefix> <IPv4 Prefix> <EA-bits length> [<a>]");

	rule_ptr = &rule;
	/* Fall through */

end:
	result.error = nla_put_mapping_rule(msg, id, rule_ptr);
	if (result.error)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result json2nl_bool(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
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

static struct jool_result __json2nl_u8(cJSON *json, struct nl_msg *msg,
		unsigned int key)
{
	struct jool_result result;

	result = validate_uint(json->string, json, 0, MAX_U8);
	if (result.error)
		return result;
	if (nla_put_u8(msg, key, json->valueuint) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result json2nl_u8(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	return __json2nl_u8(json, msg, meta->id);
}

static struct jool_result json2nl_u32(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	struct jool_result result;

	result = validate_uint(json->string, json, 0, MAX_U32);
	if (result.error)
		return result;
	if (nla_put_u32(msg, meta->id, json->valueuint) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result json2nl_string(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	switch (json->type) {
	case cJSON_String:
		return meta->type->str2nl(meta->id, json->valuestring, msg);
	case cJSON_NULL:
		return meta->type->str2nl(meta->id, "null", msg);
	}

	return type_mismatch(json->string, json, "string");
}

static struct jool_result json2nl_plateaus(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	struct nlattr *root;
	struct jool_result result;

	if (json->type != cJSON_Array)
		return type_mismatch(json->string, json, "plateaus array");

	root = jnla_nest_start(msg, JNLAG_PLATEAUS);
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

static struct jool_result j2n_prefix6(cJSON *json, struct nl_msg *msg,
		unsigned int key)
{
	struct ipv6_prefix prefix;
	struct jool_result result;

	if (json->type != cJSON_String)
		return type_mismatch(json->string, json, "String");
	result = str_to_prefix6(json->valuestring, &prefix);
	if (result.error)
		return result;
	if (nla_put_prefix6(msg, key, &prefix) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result j2n_prefix4(cJSON *json, struct nl_msg *msg,
		unsigned int key)
{
	struct ipv4_prefix prefix;
	struct jool_result result;

	if (json->type != cJSON_String)
		return type_mismatch(json->string, json, "String");
	result = str_to_prefix4(json->valuestring, &prefix);
	if (result.error)
		return result;
	if (nla_put_prefix4(msg, key, &prefix) < 0)
		return joolnl_err_msgsize();

	return result_success();
}

static struct jool_result j2n_mapping_rule(cJSON *json, struct nl_msg *msg,
		unsigned int key)
{
	struct nlattr *root;
	cJSON *child;
	struct jool_result result;

	if (json->type == cJSON_NULL) {
		root = jnla_nest_start(msg, key);
		if (!root)
			return joolnl_err_msgsize();

		if (nla_put_prefix6(msg, JNLAMR_PREFIX6, NULL) < 0) {
			nla_nest_cancel(msg, root);
			return joolnl_err_msgsize();
		}

		nla_nest_end(msg, root);
		return result_success();
	}

	if (json->type != cJSON_Object)
		return type_mismatch(json->string, json, "Object");

	root = jnla_nest_start(msg, key);
	if (!root)
		return joolnl_err_msgsize();

	for (child = json->child; child; child = child->next) {
		if (strcasecmp(child->string, "comment") == 0)
			result = result_success(); /* Skip */
		else if (strcasecmp(child->string, "IPv6 Prefix") == 0)
			result = j2n_prefix6(child, msg, JNLAMR_PREFIX6);
		else if (strcasecmp(child->string, "IPv4 Prefix") == 0)
			result = j2n_prefix4(child, msg, JNLAMR_PREFIX4);
		else if (strcasecmp(child->string, "EA-bits length") == 0)
			result = __json2nl_u8(child, msg, JNLAMR_EA_BITS_LENGTH);
		else if (strcasecmp(child->string, "a") == 0)
			result = __json2nl_u8(child, msg, JNLAMR_a);
		else
			result = result_from_error(-EINVAL, "Unknown tag: '%s'", child->string);

		if (result.error) {
			nla_nest_cancel(msg, root);
			return result;
		}
	}

	nla_nest_end(msg, root);
	return result_success();
}

static struct jool_result json2nl_mapping_rule(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	return j2n_mapping_rule(json, msg, meta->id);
}

#endif

#ifdef __KERNEL__

#define KERNEL_FUNCTIONS(_raw2nl, _nl2raw) .raw2nl = _raw2nl, .nl2raw = _nl2raw,
#define USERSPACE_FUNCTIONS(_print, _str2nl, _json2nl, _nl2raw)

#else

#define KERNEL_FUNCTIONS(_raw2nl, _nl2raw)
#define USERSPACE_FUNCTIONS(_print, _str2nl, _json2nl, _nl2raw) \
	.print = _print, \
	.str2nl = _str2nl, \
	.json2nl = _json2nl, \
	.nl2raw = _nl2raw,

#endif

static struct joolnl_global_type gt_bool = {
	.name = "Boolean",
	.candidates = "true false",
	KERNEL_FUNCTIONS(raw2nl_bool, nl2raw_bool)
	USERSPACE_FUNCTIONS(print_bool, str2nl_bool, json2nl_bool, nl2raw_bool)
};

static struct joolnl_global_type gt_uint8 = {
	.name = "8-bit unsigned integer",
	KERNEL_FUNCTIONS(raw2nl_u8, nl2raw_u8)
	USERSPACE_FUNCTIONS(print_u8, str2nl_u8, json2nl_u8, nl2raw_u8)
};

static struct joolnl_global_type gt_uint32 = {
	.name = "32-bit unsigned integer",
	KERNEL_FUNCTIONS(raw2nl_u32, nl2raw_u32)
	USERSPACE_FUNCTIONS(print_u32, str2nl_u32, json2nl_u32, nl2raw_u32)
};

static struct joolnl_global_type gt_timeout = {
	.name = "[HH:[MM:]]SS[.mmm]",
	KERNEL_FUNCTIONS(raw2nl_u32, nl2raw_u32)
	USERSPACE_FUNCTIONS(print_timeout, str2nl_timeout, json2nl_string, nl2raw_u32)
};

static struct joolnl_global_type gt_plateaus = {
	.name = "List of 16-bit unsigned integers separated by commas",
	KERNEL_FUNCTIONS(raw2nl_plateaus, nl2raw_plateaus)
	USERSPACE_FUNCTIONS(print_plateaus, str2nl_plateaus, json2nl_plateaus, nl2raw_plateaus)
};

static struct joolnl_global_type gt_prefix6 = {
	.name = "IPv6 prefix",
	KERNEL_FUNCTIONS(raw2nl_prefix6, nl2raw_prefix6)
	USERSPACE_FUNCTIONS(print_prefix6, str2nl_prefix6, json2nl_string, nl2raw_prefix6)
};

static struct joolnl_global_type gt_prefix4 = {
	.name = "IPv4 prefix",
	KERNEL_FUNCTIONS(raw2nl_prefix4, NULL)
	USERSPACE_FUNCTIONS(print_prefix4, str2nl_prefix4, json2nl_string, nl2raw_prefix4)
};

static struct joolnl_global_type gt_hairpin_mode = {
	.name = "Hairpinning Mode",
	.candidates = "off simple intrinsic",
	KERNEL_FUNCTIONS(raw2nl_u8, nl2raw_hairpin_mode)
	USERSPACE_FUNCTIONS(print_hairpin_mode, str2nl_hairpin_mode, json2nl_string, nl2raw_u8)
};

static struct joolnl_global_type gt_maptype = {
	.name = "MAP-T type",
	.candidates = "CE BR",
	KERNEL_FUNCTIONS(raw2nl_u8, nl2raw_maptype)
	USERSPACE_FUNCTIONS(print_maptype, str2nl_maptype, json2nl_string, nl2raw_u8)
};

static struct joolnl_global_type gt_mapping_rule = {
	.name = "MAP-T Mapping Rule",
	KERNEL_FUNCTIONS(raw2nl_mapping_rule, nl2raw_mapping_rule)
	USERSPACE_FUNCTIONS(print_mapping_rule, str2nl_mapping_rule, json2nl_mapping_rule, nl2raw_mapping_rule)
};

static const struct joolnl_global_meta globals_metadata[] = {
	{
		.id = JNLAG_ENABLED,
		.name = "manually-enabled",
		.type = &gt_bool,
		.doc = "Resumes or pauses the instance's translation.",
		.offset = offsetof(struct jool_globals, enabled),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_POOL6,
		.name = "pool6",
		.type = &gt_prefix6,
		.doc = "The IPv6 Address Pool prefix.",
		.offset = offsetof(struct jool_globals, pool6),
		.xt = XT_ANY,
		.candidates = TYPICAL_XLAT_PREFIXES,
#ifdef __KERNEL__
		.nl2raw = nl2raw_pool6,
#endif
	}, {
		.id = JNLAG_LOWEST_IPV6_MTU,
		.name = "lowest-ipv6-mtu",
		.type = &gt_uint32,
		.doc = "Smallest reachable IPv6 MTU.",
		.offset = offsetof(struct jool_globals, lowest_ipv6_mtu),
		.xt = XT_ANY,
#ifdef __KERNEL__
		.nl2raw = nl2raw_lowest_ipv6_mtu,
#endif
	}, {
		.id = JNLAG_DEBUG,
		.name = "logging-debug",
		.type = &gt_bool,
		.doc = "Pour lots of debugging messages on the log?",
		.offset = offsetof(struct jool_globals, debug),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_RESET_TC,
		.name = "zeroize-traffic-class",
		.type = &gt_bool,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
		.offset = offsetof(struct jool_globals, reset_traffic_class),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_RESET_TOS,
		.name = "override-tos",
		.type = &gt_bool,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
		.offset = offsetof(struct jool_globals, reset_tos),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_TOS,
		.name = "tos",
		.type = &gt_uint8,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
		.offset = offsetof(struct jool_globals, new_tos),
		.xt = XT_ANY,
	} , {
		.id = JNLAG_PLATEAUS,
		.name = "mtu-plateaus",
		.type = &gt_plateaus,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
		.offset = offsetof(struct jool_globals, plateaus),
		.xt = XT_ANY,
	}, {
		.id = JNLAG_COMPUTE_CSUM_ZERO,
		.name = "amend-udp-checksum-zero",
		.type = &gt_bool,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.",
		.offset = offsetof(struct jool_globals, siit.compute_udp_csum_zero),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_HAIRPIN_MODE,
		.name = "eam-hairpin-mode",
		.type = &gt_hairpin_mode,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.offset = offsetof(struct jool_globals, siit.eam_hairpin_mode),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_RANDOMIZE_ERROR_ADDR,
		.name = "randomize-rfc6791-addresses",
		.type = &gt_bool,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.",
		.offset = offsetof(struct jool_globals, randomize_error_addresses),
		.xt = XT_SIIT,
	}, {
		.id = JNLAG_POOL6791V6,
		.name = "rfc6791v6-prefix",
		.type = &gt_prefix6,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.offset = offsetof(struct jool_globals, rfc6791_prefix6),
		.xt = XT_SIIT | XT_MAPT,
	}, {
		.id = JNLAG_POOL6791V4,
		.name = "rfc6791v4-prefix",
		.type = &gt_prefix4,
		.doc = "IPv4 prefix to generate RFC6791 addresses from.",
		.offset = offsetof(struct jool_globals, rfc6791_prefix4),
		.xt = XT_SIIT | XT_MAPT,
#ifdef __KERNEL__
		.nl2raw = nl2raw_pool6791v4,
#endif
	}, {
		.id = JNLAG_DROP_BY_ADDR,
		.name = "address-dependent-filtering",
		.type = &gt_bool,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
		.offset = offsetof(struct jool_globals, nat64.bib.drop_by_addr),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_DROP_EXTERNAL_TCP,
		.name = "drop-externally-initiated-tcp",
		.type = &gt_bool,
		.doc = "Drop externally initiated TCP connections?",
		.offset = offsetof(struct jool_globals, nat64.bib.drop_external_tcp),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_DROP_ICMP6_INFO,
		.name = "drop-icmpv6-info",
		.type = &gt_bool,
		.doc = "Filter ICMPv6 Informational packets?",
		.offset = offsetof(struct jool_globals, nat64.drop_icmp6_info),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_SRC_ICMP6_BETTER,
		.name = "source-icmpv6-errors-better",
		.type = &gt_bool,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?",
		.offset = offsetof(struct jool_globals, nat64.src_icmp6errs_better),
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
		.offset = offsetof(struct jool_globals, nat64.f_args),
		.xt = XT_NAT64,
#ifdef __KERNEL__
		.nl2raw = nl2raw_f_args,
#else
		.print = print_fargs,
#endif
	}, {
		.id = JNLAG_HANDLE_RST,
		.name = "handle-rst-during-fin-rcv",
		.type = &gt_bool,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
		.offset = offsetof(struct jool_globals, nat64.handle_rst_during_fin_rcv),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_TTL_TCP_EST,
		.name = "tcp-est-timeout",
		.type = &gt_timeout,
		.doc = "Set the TCP established session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct jool_globals, nat64.bib.ttl.tcp_est),
		.xt = XT_NAT64,
#ifdef __KERNEL__
		.nl2raw = nl2raw_ttl_tcp_est,
#endif
	}, {
		.id = JNLAG_TTL_TCP_TRANS,
		.name = "tcp-trans-timeout",
		.type = &gt_timeout,
		.doc = "Set the TCP transitory session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct jool_globals, nat64.bib.ttl.tcp_trans),
		.xt = XT_NAT64,
#ifdef __KERNEL__
		.nl2raw = nl2raw_ttl_tcp_trans,
#endif
	}, {
		.id = JNLAG_TTL_UDP,
		.name = "udp-timeout",
		.type = &gt_timeout,
		.doc = "Set the UDP session lifetime (HH:MM:SS.mmm).",
		.offset = offsetof(struct jool_globals, nat64.bib.ttl.udp),
		.xt = XT_NAT64,
#ifdef __KERNEL__
		.nl2raw = nl2raw_ttl_udp,
#endif
	}, {
		.id = JNLAG_TTL_ICMP,
		.name = "icmp-timeout",
		.type = &gt_timeout,
		.doc = "Set the timeout for ICMP sessions (HH:MM:SS.mmm).",
		.offset = offsetof(struct jool_globals, nat64.bib.ttl.icmp),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_BIB_LOGGING,
		.name = "logging-bib",
		.type = &gt_bool,
		.doc = "Log BIBs as they are created and destroyed?",
		.offset = offsetof(struct jool_globals, nat64.bib.bib_logging),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_SESSION_LOGGING,
		.name = "logging-session",
		.type = &gt_bool,
		.doc = "Log sessions as they are created and destroyed?",
		.offset = offsetof(struct jool_globals, nat64.bib.session_logging),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_MAX_STORED_PKTS,
		.name = "maximum-simultaneous-opens",
		.type = &gt_uint32,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.",
		.offset = offsetof(struct jool_globals, nat64.bib.max_stored_pkts),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_ENABLED,
		.name = "ss-enabled",
		.type = &gt_bool,
		.doc = "Enable Session Synchronization?",
		.offset = offsetof(struct jool_globals, nat64.joold.enabled),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_FLUSH_ASAP,
		.name = "ss-flush-asap",
		.type = &gt_bool,
		.doc = "Try to synchronize sessions as soon as possible?",
		.offset = offsetof(struct jool_globals, nat64.joold.flush_asap),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_FLUSH_DEADLINE,
		.name = "ss-flush-deadline",
		.type = &gt_uint32,
		.doc = "Inactive milliseconds after which to force a session sync.",
		.offset = offsetof(struct jool_globals, nat64.joold.flush_deadline),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_CAPACITY,
		.name = "ss-capacity",
		.type = &gt_uint32,
		.doc = "Maximim number of queuable entries.",
		.offset = offsetof(struct jool_globals, nat64.joold.capacity),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_JOOLD_MAX_PAYLOAD,
		.name = "ss-max-payload",
		.type = &gt_uint32,
		.doc = "Maximum amount of bytes joold should send per packet.",
		.offset = offsetof(struct jool_globals, nat64.joold.max_payload),
		.xt = XT_NAT64,
	}, {
		.id = JNLAG_MAPTYPE,
		.name = "map-t-type",
		.type = &gt_maptype,
		.doc = "CE or BR.",
		.offset = offsetof(struct jool_globals, mapt.type),
		.xt = XT_MAPT,
	}, {
		.id = JNLAG_EUI6P,
		.name = "end-user-ipv6-prefix",
		.type = &gt_prefix6,
		.doc = "The prefix identifier of this CE.",
		.offset = offsetof(struct jool_globals, mapt.eui6p),
		.xt = XT_MAPT,
	}, {
		.id = JNLAG_BMR,
		.name = "bmr",
		.type = &gt_mapping_rule,
		.doc = "The MAP domain's common configuration.",
		.offset = offsetof(struct jool_globals, mapt.bmr),
		.xt = XT_MAPT,
	}
};

static const unsigned int globals_metadata_len = sizeof(globals_metadata)
		/ sizeof(globals_metadata[0]);

struct joolnl_global_meta const *joolnl_global_meta_first(void)
{
	return globals_metadata;
}

struct joolnl_global_meta const *joolnl_global_meta_last(void)
{

	return &globals_metadata[globals_metadata_len - 1];
}

struct joolnl_global_meta const *joolnl_global_meta_next(
		struct joolnl_global_meta const *pos)
{
	return pos + 1;
}

unsigned int joolnl_global_meta_count(void)
{
	return globals_metadata_len;
}

struct joolnl_global_meta const *joolnl_global_id2meta(enum joolnl_attr_global id)
{
	struct joolnl_global_meta const *meta;

	if (id < 1 || JNLAG_MAX < id)
		return NULL;
	if (id == globals_metadata[id - 1].id)
		return &globals_metadata[id - 1];

#ifdef __KERNEL__
	pr_err("The globals metadata array is not properly sorted.\n");
#else
	fprintf(stderr, "The globals metadata array is not properly sorted.\n");
#endif

	joolnl_global_foreach_meta(meta)
		if (meta->id == id)
			return meta;

	return NULL;
}

enum joolnl_attr_global joolnl_global_meta_id(
		struct joolnl_global_meta const *meta)
{
	return meta->id;
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

void *joolnl_global_get(struct joolnl_global_meta const *meta, struct jool_globals *cfg)
{
	return ((unsigned char *)cfg) + meta->offset;
}

#ifdef __KERNEL__

int joolnl_global_raw2nl(struct joolnl_global_meta const *meta, void *raw,
		struct sk_buff *skb, struct jnl_state *state)
{
	if (!meta->type->raw2nl) {
		return jnls_err(state, "The raw2nl callback of type '%s' is undefined.",
				meta->type->name);
	}

	return meta->type->raw2nl(meta, raw, skb);
}

int joolnl_global_nl2raw(struct joolnl_global_meta const *meta,
		struct nlattr *nl, void *raw, bool force,
		struct jnl_state *state)
{
	joolnl_global_nl2raw_fn nl2raw;

	if (meta->nl2raw)
		nl2raw = meta->nl2raw;
	else if (meta->type->nl2raw)
		nl2raw = meta->type->nl2raw;
	else {
		return jnls_err(state, "Global '%s' has no nl2raw function, and its type doesn't either.",
				meta->name);
	}

	return nl2raw(meta, nl, raw, force, state);
}

#else

struct jool_result joolnl_global_nl2raw(struct joolnl_global_meta const *meta,
		struct nlattr *nl, void *raw)
{
	if (!meta->type->nl2raw) {
		return result_from_error(
			-EINVAL,
			"The nl2raw callback of type '%s' is undefined.",
			meta->type->name
		);
	}

	return meta->type->nl2raw(nl, raw);
}

struct jool_result joolnl_global_str2nl(struct joolnl_global_meta const *meta,
		char const *str, struct nl_msg *nl)
{
	if (!meta->type->str2nl) {
		return result_from_error(
			-EINVAL,
			"The str2nl callback of type '%s' is undefined.",
			meta->type->name
		);
	}

	return meta->type->str2nl(meta->id, str, nl);
}

struct jool_result joolnl_global_json2nl(struct joolnl_global_meta const *meta,
		cJSON *json, struct nl_msg *msg)
{
	if (!meta->type->json2nl) {
		return result_from_error(
			-EINVAL,
			"The json2nl callback of type '%s' is undefined.",
			meta->type->name
		);
	}

	return meta->type->json2nl(meta, json, msg);
}

void joolnl_global_print(struct joolnl_global_meta const *meta, void *value,
		bool csv)
{
	joolnl_global_print_fn print;

	if (meta->print)
		print = meta->print;
	else if (meta->type->print)
		print = meta->type->print;
	else {
		fprintf(stderr, "Global '%s' has no print function, and its type doesn't either.\n",
				meta->name);
		return;
	}

	print(value, csv);
}

#endif
