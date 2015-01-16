#include "nat64/usr/str_utils.h"
#include "nat64/comm/constants.h"
#include "nat64/usr/types.h"
#include "nat64/comm/nat64.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>


#define MAX_PORT 0xFFFF

/* The maximum network length for IPv4. */
static const __u8 IPV4_PREFIX = 32;
/* The maximum network length for IPv6. */
static const __u8 IPV6_PREFIX = 128;

const char *l3proto_to_string(l3_protocol l3_proto)
{
	switch (l3_proto) {
	case L3PROTO_IPV6:
		return "IPv6";
	case L3PROTO_IPV4:
		return "IPv4";
	}

	return NULL;
}

const char *l4proto_to_string(l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_TCP:
		return "TCP";
	case L4PROTO_UDP:
		return "UDP";
	case L4PROTO_ICMP:
		return "ICMP";
	}

	return NULL;
}

int str_to_bool(const char *str, __u8 *bool_out)
{
	if (strcasecmp(str, "true") == 0 || strcasecmp(str, "1") == 0
			|| strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0) {
		*bool_out = true;
		return 0;
	}

	if (strcasecmp(str, "false") == 0 || strcasecmp(str, "0") == 0
			|| strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0) {
		*bool_out = false;
		return 0;
	}

	log_err("Cannot parse '%s' as a boolean (true|false|1|0|yes|no|on|off).", str);
	return -EINVAL;
}

int str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	__u64 result;
	int error;

	error = str_to_u64(str, &result, (__u64) min, (__u64) max);
	if (error)
		return error; /* Error msg already printed. */

	*u8_out = result;
	return 0;
}

int str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	__u64 result;
	int error;

	error = str_to_u64(str, &result, (__u64) min, (__u64) max);
	if (error)
		return error; /* Error msg already printed. */

	*u16_out = result;
	return 0;
}

int str_to_u64(const char *str, __u64 *u64_out, __u64 min, __u64 max)
{
	__u64 result;
	char *endptr;

	errno = 0;
	result = strtoull(str, &endptr, 10);
	if (errno != 0 || str == endptr) {
		log_err("Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err("'%s' is out of bounds (%llu-%llu).", str, min, max);
		return -EINVAL;
	}

	*u64_out = result;
	return 0;
}

#define STR_MAX_LEN 2048
int str_to_u16_array(const char *str, __u16 **array_out, size_t *array_len_out)
{
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	__u16 *array;
	size_t array_len;

	/* Validate str and copy it to the temp buffer. */
	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	/* Count the number of ints in the string. */
	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		array_len++;
		token = strtok(NULL, ",");
	}

	if (array_len == 0) {
		log_err("'%s' seems to be an empty list, which is not supported.", str);
		return -EINVAL;
	}

	/* Build the result. */
	array = malloc(array_len * sizeof(*array));
	if (!array) {
		log_err("Memory allocation failed. Cannot parse the input...");
		return -ENOMEM;
	}

	strcpy(str_copy, str);

	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		int error;

		error = str_to_u16(token, &array[array_len], 0, 0xFFFF);
		if (error) {
			free(array);
			return error; /* Error msg already printed. */
		}

		array_len++;
		token = strtok(NULL, ",");
	}

	/* Finish. */
	*array_out = array;
	*array_len_out = array_len;
	return 0;
}

int str_to_addr4(const char *str, struct in_addr *result)
{
	if (!inet_pton(AF_INET, str, result)) {
		log_err("Cannot parse '%s' as an IPv4 address.", str);
		return -EINVAL;
	}
	return 0;
}

int str_to_addr6(const char *str, struct in6_addr *result)
{
	if (!inet_pton(AF_INET6, str, result)) {
		log_err("Cannot parse '%s' as an IPv6 address.", str);
		return -EINVAL;
	}
	return 0;
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET_ADDRSTRLEN + 1 + 5) /* [addr + null chara] + # + port */
int str_to_addr4_port(const char *str, struct ipv4_transport_addr *addr_out)
{
	const char *FORMAT = "<IPv4 address>#<port> (eg. 10.20.30.40#50)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr4(token, &addr_out->l3);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err("'%s' does not seem to contain a port (format: %s).", str, FORMAT);
		return -EINVAL;
	}
	error = str_to_u16(token, &addr_out->l4, 0, MAX_PORT);
	if (error)
		return error; /* Error msg already printed. */

	return 0;
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET6_ADDRSTRLEN + 1 + 5) /* [addr + null chara] + # + port */
int str_to_addr6_port(const char *str, struct ipv6_transport_addr *addr_out)
{
	const char *FORMAT = "<IPv6 address>#<port> (eg. 64:ff9b::#96)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr6(token, &addr_out->l3);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err("'%s' does not seem to contain a port (format: %s).", str, FORMAT);
		return -EINVAL;
	}
	error = str_to_u16(token, &addr_out->l4, 0, MAX_PORT);
	if (error)
		return error; /* Error msg already printed. */

	return 0;
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET6_ADDRSTRLEN + 1 + 3) /* [addr + null chara] + / + pref len */
int str_to_ipv6_prefix(const char *str, struct ipv6_prefix *prefix_out)
{
	const char *FORMAT = "<IPv6 address>/<length> (eg. 64:ff9b::/96)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	__u8 valid_lengths[] = POOL6_PREFIX_LENGTHS;
	int valid_lengths_size = sizeof(valid_lengths) / sizeof(valid_lengths[0]);
	int i;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr6(token, &prefix_out->address);
	if (error)
		return error;

	token = strtok(NULL, "/");
	if (!token) {
		if (!nat64_is_stateful()) {
			prefix_out->len = IPV6_PREFIX;
			return 0;
		}
		log_err("'%s' does not seem to contain a mask (format: %s).", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_u8(token, &prefix_out->len, 0, 0xFF);
	if (error)
		return error; /* Error msg already printed. */

	if (!nat64_is_stateful())
		return 0;

	for (i = 0; i < valid_lengths_size; i++)
		if (prefix_out->len == valid_lengths[i])
			return 0;

	log_err("%u is not a valid prefix length.", prefix_out->len);
	return -EINVAL;
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET_ADDRSTRLEN + 1 + 2) /* [addr + null chara] + / + pref len */
int str_to_ipv4_prefix(const char *str, struct ipv4_prefix *prefix_out)
{
	const char *FORMAT = "<IPv4 address>/<length> (eg. 192.168.1.0/24)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr4(token, &prefix_out->address);
	if (error)
		return error;

	token = strtok(NULL, "/");
	if (!token) {
		if (!nat64_is_stateful()) {
			prefix_out->len = IPV4_PREFIX;
			return 0;
		}
		log_err("'%s' does not seem to contain a mask (format: %s).", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_u8(token, &prefix_out->len, 0, 0xFF);
	return error; /* Error msg already printed. */
}

static void print_num_csv(__u64 num, char *separator)
{
	if (num < 10)
		printf("0%llu%s", num, separator);
	else
		printf("%llu%s", num, separator);
}

void print_time_csv(__u64 millis)
{
	const __u64 MILLIS_PER_SECOND = 1000;
	const __u64 MILLIS_PER_MIN = 60 * MILLIS_PER_SECOND;
	const __u64 MILLIS_PER_HOUR = 60 * MILLIS_PER_MIN;
	__u64 hours;
	__u64 minutes;
	__u64 seconds;

	hours = millis / MILLIS_PER_HOUR;
	millis -= hours * MILLIS_PER_HOUR;

	minutes = millis / MILLIS_PER_MIN;
	millis -= minutes * MILLIS_PER_MIN;

	seconds = millis / MILLIS_PER_SECOND;
	millis -= seconds * MILLIS_PER_SECOND;

	print_num_csv(hours, ":");
	print_num_csv(minutes, ":");
	print_num_csv(seconds, ".");
	printf("%llu", millis);
}

void print_time_friendly(__u64 millis)
{
	__u64 seconds;
	__u64 minutes;
	__u64 hours;

	if (millis < 1000) {
		printf("%llu milliseconds\n", millis);
		return;
	}

	seconds = millis / 1000;

	if (seconds < 60) {
		printf("%llu seconds\n", seconds);
		return;
	}

	minutes = seconds / 60;
	seconds %= 60;

	if (minutes < 60) {
		printf("%llu minutes, %llu seconds\n", minutes, seconds);
		return;
	}

	hours = minutes / 60;
	minutes %= 60;

	printf("%llu hours, %llu minutes\n", hours, minutes);
}
