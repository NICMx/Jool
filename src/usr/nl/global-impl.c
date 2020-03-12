#include "common/globals.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/config.h"
#include "usr/util/cJSON.h"
#include "usr/util/str_utils.h"
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"

void print_bool(void *value, bool csv)
{
	bool bvalue = *((bool *)value);
	if (csv)
		printf("%s", bvalue ? "TRUE" : "FALSE");
	else
		printf("%s", bvalue ? "true" : "false");
}

void print_u8(void *value, bool csv)
{
	__u8 *uvalue = value;
	printf("%u", *uvalue);
}

void print_u32(void *value, bool csv)
{
	__u32 *uvalue = value;
	printf("%u", *uvalue);
}

void print_timeout(void *value, bool csv)
{
	__u32 *uvalue = value;
	char string[TIMEOUT_BUFLEN];

	timeout2str(*uvalue, string);
	printf("%s", string);

	if (!csv)
		printf(" (HH:MM:SS)");
}

void print_plateaus(void *value, bool csv)
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

void print_prefix6(void *value, bool csv)
{
	struct config_prefix6 *prefix = value;
	print_prefix(AF_INET6, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set, csv);
}

void print_prefix4(void *value, bool csv)
{
	struct config_prefix4 *prefix = value;
	print_prefix(AF_INET, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set, csv);
}

void print_hairpin_mode(void *value, bool csv)
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

void print_fargs(void *value, bool csv)
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

struct jool_result packetize_bool(struct nl_msg *msg,
		struct global_field const *field, char const *string)
{
	bool value;
	struct jool_result result;

	result = str_to_bool(string, &value);
	if (result.error)
		return result;

	return (nla_put_u8(msg, field->id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_u8(struct nl_msg *msg,
		struct global_field const *field, char const *string)
{
	__u8 value;
	struct jool_result result;

	result = str_to_u8(string, &value, field->min, field->max);
	if (result.error)
		return result;

	return (nla_put_u8(msg, field->id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_u32(struct nl_msg *msg,
		struct global_field const *field, char const *string)
{
	__u32 value;
	struct jool_result result;

	result = str_to_u32(string, &value, field->min, field->max);
	if (result.error)
		return result;

	return (nla_put_u32(msg, field->id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_timeout(struct nl_msg *msg,
		struct global_field const *field, char const *string)
{
	__u32 value;
	struct jool_result result;

	result = str_to_timeout(string, &value, field->min, field->max);
	if (result.error)
		return result;

	return (nla_put_u32(msg, field->id, value) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_plateaus(struct nl_msg *msg,
		struct global_field const *field, char const *string)
{
	struct mtu_plateaus plateaus;
	struct jool_result result;

	result = str_to_plateaus_array(string, &plateaus);
	if (result.error)
		return result;

	return (nla_put_plateaus(msg, field->id, &plateaus) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_prefix6(struct nl_msg *msg,
		struct global_field const *field, char const *string)
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

	return (nla_put_prefix6(msg, field->id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_prefix4(struct nl_msg *msg,
		struct global_field const *field, char const *string)
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

	return (nla_put_prefix4(msg, field->id, prefix_ptr) < 0)
			? joolnl_err_msgsize()
			: result_success();
}

struct jool_result packetize_hairpin_mode(struct nl_msg *msg,
		struct global_field const *field, char const *string)
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

	return (nla_put_u8(msg, field->id, mode) < 0)
			? joolnl_err_msgsize()
			: result_success();
}
