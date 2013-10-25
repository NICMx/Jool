#include "nat64/comm/str_utils.h"
#include "nat64/comm/constants.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>


#define MAX_PORT 0xFFFF

int str_to_bool(const char *str, bool *bool_out)
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

	log_err(ERR_PARSE_BOOL, "Cannot parse '%s' as a boolean (true|false|1|0|yes|no|on|off).", str);
	return -EINVAL;
}

int str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	__u16 result;
	int error;

	error = str_to_u16(str, &result, min, max);
	if (error)
		return error; /* Error msg already printed. */

	*u8_out = result;
	return 0;
}

int str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	long result;
	char *endptr;

	errno = 0;
	result = strtol(str, &endptr, 10);
	if (errno != 0 || str == endptr) {
		log_err(ERR_PARSE_INT, "Cannot parse '%s' as an integer value.", str);
		return -EINVAL;
	}
	if (result < min || max < result) {
		log_err(ERR_INT_OUT_OF_BOUNDS, "'%s' is out of bounds (%u-%u).", str, min, max);
		return -EINVAL;
	}

	*u16_out = result;
	return 0;
}

int str_to_u16_array(const char *str, __u16 **array_out, __u16 *array_len_out)
{
	const unsigned int str_max_len = 2048;
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[str_max_len];
	char *token;
	__u16 *array;
	__u16 array_len;

	/* Validate str and copy it to the temp buffer. */
	if (strlen(str) + 1 > str_max_len) {
		log_err(ERR_PARSE_INTARRAY, "'%s' is too long for this poor, limited parser...", str);
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
		log_err(ERR_PARSE_INTARRAY, "'%s' seems to be an empty list, which is not supported.", str);
		return -EINVAL;
	}

	/* Build the result. */
	array = malloc(array_len * sizeof(__u16));
	if (!array) {
		log_err(ERR_ALLOC_FAILED, "Memory allocation failed. Cannot parse the input...");
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
		log_err(ERR_PARSE_ADDR4, "Cannot parse '%s' as a IPv4 address.", str);
		return -EINVAL;
	}
	return 0;
}

int str_to_addr6(const char *str, struct in6_addr *result)
{
	if (!inet_pton(AF_INET6, str, result)) {
		log_err(ERR_PARSE_ADDR6, "Cannot parse '%s' as a IPv6 address.", str);
		return -EINVAL;
	}
	return 0;
}

int str_to_addr4_port(const char *str, struct ipv4_tuple_address *addr_out)
{
	const char *FORMAT = "<IPv4 address>#<port> (eg. 10.20.30.40#50)";
	/* [addr + null chara] + # + port */
	const unsigned int STR_MAX_LEN = INET_ADDRSTRLEN + 1 + 5;
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err(ERR_PARSE_ADDR4_PORT, "'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err(ERR_PARSE_ADDR4_PORT, "Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr4(token, &addr_out->address);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err(ERR_PARSE_ADDR4_PORT, "'%s' does not seem to contain a port (format: %s).", str,
				FORMAT);
		return -EINVAL;
	}
	error = str_to_u16(token, &addr_out->l4_id, 0, MAX_PORT);
	if (error)
		return error; /* Error msg already printed. */

	return 0;
}

int str_to_addr6_port(const char *str, struct ipv6_tuple_address *addr_out)
{
	const char *FORMAT = "<IPv6 address>#<port> (eg. 64:ff9b::#96)";
	const unsigned int STR_MAX_LEN = INET6_ADDRSTRLEN + 1 + 5; /* [addr + null chara] + # + port */
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err(ERR_PARSE_ADDR6_PORT, "'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err(ERR_PARSE_ADDR6_PORT, "Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr6(token, &addr_out->address);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err(ERR_PARSE_ADDR6_PORT, "'%s' does not seem to contain a port (format: %s).", str,
				FORMAT);
		return -EINVAL;
	}
	error = str_to_u16(token, &addr_out->l4_id, 0, MAX_PORT);
	if (error)
		return error; /* Error msg already printed. */

	return 0;
}

int str_to_prefix(const char *str, struct ipv6_prefix *prefix_out)
{
	const char *FORMAT = "<IPv6 address>/<length> (eg. 64:ff9b::/96)";
	/* [addr + null chara] + / + pref len */
	const unsigned int STR_MAX_LEN = INET6_ADDRSTRLEN + 1 + 3;
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	__u8 valid_lengths[] = POOL6_PREFIX_LENGTHS;
	int valid_lengths_size = sizeof(valid_lengths) / sizeof(valid_lengths[0]);
	int i;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err(ERR_PARSE_PREFIX, "'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token) {
		log_err(ERR_PARSE_PREFIX, "Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr6(token, &prefix_out->address);
	if (error)
		return error;

	token = strtok(NULL, "/");
	if (!token) {
		log_err(ERR_PARSE_PREFIX, "'%s' does not seem to contain a mask (format: %s).", str, FORMAT);
		return -EINVAL;
	}
	error = str_to_u8(token, &prefix_out->len, 0, 0xFF);
	if (error)
		return error; /* Error msg already printed. */

	for (i = 0; i < valid_lengths_size; i++)
		if (prefix_out->len == valid_lengths[i])
			return 0;

	log_err(ERR_PREF_LEN_RANGE, "%u is not a valid prefix length.", prefix_out->len);
	return -EINVAL;
}

static char *get_error_msg(enum error_code code)
{
	switch (code) {
	case ERR_SUCCESS:
		return NULL;
	case ERR_NULL:
		return "'NULL' is not a legal value.";
	case ERR_L4PROTO:
		return "Unsupported transport protocol.";
	case ERR_L3PROTO:
		return "Unsupported network protocol.";
	case ERR_ALLOC_FAILED:
		return "A memory allocation failed, so the handling of the request could not be completed.";
	case ERR_MISSING_FRAG_HEADER:
		return "Missing fragment header in a IPv6 packet.";
	case ERR_UNKNOWN_ERROR:
		return "Unknown error.";

	case ERR_NETLINK:
		return "Could not connect to the NAT64 (Is it really up?).";
	case ERR_MTU_LIST_EMPTY:
		return "The list of plateaus must contain at least one element.";
	case ERR_MTU_LIST_ZEROES:
		return "The list of plateaus must contain positive numbers.";
	case ERR_UDP_TO_RANGE:
		return "The UDP timeout is out of range.";
	case ERR_TCPEST_TO_RANGE:
		return "The TCP established timeout is out of range.";
	case ERR_TCPTRANS_TO_RANGE:
		return "The TCP transitory timeout is out of range.";
	case ERR_PARSE_BOOL:
		return "Unable to parse value as a boolean.";
	case ERR_PARSE_INT:
		return "Unable to parse value as an integer.";
	case ERR_INT_OUT_OF_BOUNDS:
		return "Integer out of bounds.";
	case ERR_PARSE_INTARRAY:
		return "Invalid list of integers. Please provide numbers separated by commas. If you need "
				"spaces, please surround the entire list with quotes.";
	case ERR_PARSE_ADDR4:
		return "Could not parse the input as a IPv4 address (eg. '192.168.2.1').";
	case ERR_PARSE_ADDR6:
		return "Could not parse the input as a IPv6 address (eg. '12ab:450::1').";
	case ERR_PARSE_ADDR4_PORT:
		return "Could not parse the input as a IPv4 address and port (eg. '192.168.2.1#2048').";
	case ERR_PARSE_ADDR6_PORT:
		return "Could not parse the input as a IPv6 address and port (eg. '12ab:450::1#2048').";
	case ERR_PARSE_PREFIX:
		return "Could not parse the input as a IPv6 prefix (eg. '12ab:450::/2048').";
	case ERR_UNKNOWN_OP:
		return "Unknown configuration operation.";
	case ERR_MISSING_PARAM:
		return "Missing input value.";
	case ERR_EMPTY_COMMAND:
		return "The command is empty. Type in 'nat64 --help' for instructions.";
	case ERR_PREF_LEN_RANGE:
		return "The prefix length is invalid (Try 32, 40, 48, 56, 64 or 96).";
	case ERR_POOL6_NOT_FOUND:
		return "The requested entry could not be found in the IPv6 pool.";
	case ERR_POOL4_NOT_FOUND:
		return "The requested entry could not be found in the IPv4 pool.";
	case ERR_POOL4_REINSERT:
		return "The address is already part of the pool.";
	case ERR_BIB_NOT_FOUND:
		return "The entry you just tried to remove does not exist in the table.";
	case ERR_BIB_REINSERT:
		return "There's a mapping in the table that conflicts with the one being inserted.";

	case ERR_INVALID_ITERATOR:
		return "A internal iterator is corrupted.";

	case ERR_POOL4_EMPTY:
		return "The IPv4 is empty! Please throw in addresses, so the NAT64 can translate.";
	case ERR_POOL6_EMPTY:
		return "The IPv6 is empty! Please throw in prefixes, so the NAT64 can translate.";
	case ERR_INCOMPLETE_INDEX_BIB:
		return "Some address seems to net be referenced from every table on the BIB.";
	case ERR_SESSION_NOT_FOUND:
		return "The requested entry could not be found in the Session table.";
	case ERR_SESSION_BIBLESS:
		return "Cannot store a session that has no BIB entry.";
	case ERR_INCOMPLETE_REMOVE:
		return "Could not de-index the session correctly.";

	case ERR_CONNTRACK:
		return "Conntrack did not build a tuple for the current packet.";
	case ERR_EXTRACT_FAILED:
		return "Could not translate the packet's IPv6 address to a IPv4 address.";
	case ERR_APPEND_FAILED:
		return "Could not translate the packet's IPv4 address to a IPv6 address.";
	case ERR_ADD_BIB_FAILED:
		return "Could not add the BIB entry we just created to the table.";
	case ERR_ADD_SESSION_FAILED:
		return "Could not add the session entry we just created to the table.";
	case ERR_INVALID_STATE:
		return "I ran to a session entry in a unrecognized state.";
	case ERR_MISSING_BIB:
		return "I just created a BIB entry and it dissapeared (Its lifetime is THAT short?).";
	case ERR_INNER_PACKET:
		return "Error while trying to translate the packet's inner packet.";
	case ERR_ROUTE_FAILED:
		return "The kernel could not route the packet I want to send.";
	case ERR_SEND_FAILED:
		return "The kernel could not send the packet I just translated.";

	case ERR_FRAGMENTATION_TO_RANGE:
		return "The fragmentation timeout is out of range.";
	}

	return "Unknown result code.";
}

void print_code_msg(enum error_code code, char *success_msg)
{
	if (code == ERR_SUCCESS) {
		log_info("%s", success_msg);
		return;
	}

	log_err(code, "%s", get_error_msg(code));
}

void print_time(__u64 millis)
{
	__u64 seconds;
	__u64 minutes;
	__u64 hours;

	if (millis < 1000) {
		printf("%lu milliseconds\n", millis);
		return;
	}

	seconds = millis / 1000;

	if (seconds < 60) {
		printf("%lu seconds\n", seconds);
		return;
	}

	minutes = seconds / 60;
	seconds %= 60;

	if (minutes < 60) {
		printf("%lu minutes, %lu seconds\n", minutes, seconds);
		return;
	}

	hours = minutes / 60;
	minutes %= 60;

	printf("%lu hours, %lu minutes\n", hours, minutes);
}
