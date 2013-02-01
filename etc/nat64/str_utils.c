#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include "str_utils.h"

#define MAX_PORT 0xFFFF

bool str_to_bool(const char *str, bool *bool_out)
{
	if (strcmp(str, "true") == 0 || strcmp(str, "1") == 0 || strcmp(str, "yes") == 0) {
		*bool_out = true;
		return true;
	}

	if (strcmp(str, "false") == 0 || strcmp(str, "0") == 0 || strcmp(str, "no") == 0) {
		*bool_out = false;
		return true;
	}

	printf("Error: Cannot parse '%s' as a boolean value (true|1|yes|false|0|no).\n", str);
	return false;
}

bool str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	__u16 result;
	if (!str_to_u16(str, &result, min, max))
		return false; // Error msg already printed.
	*u8_out = result;
	return true;
}

bool str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	long result;

	errno = 0;
	result = strtol(str, NULL, 10);
	if (errno != 0) {
		printf("Error: Cannot parse '%s' as an integer value.\n", str);
		return false;
	}
	if (result < min || max < result) {
		printf("Error: '%s' is out of bounds (%u-%u).\n", str, min, max);
		return false;
	}

	*u16_out = result;
	return true;
}

bool str_to_u16_array(const char *str, __u16 **array_out, __u16 *array_len_out)
{
	const int str_max_len = 2048;
	char str_copy[str_max_len]; // strtok corrupts the string, so we'll be using this copy instead.
	char *token;
	__u16 *array;
	__u16 array_len;

	// Validate str and copy it to the temp buffer.
	if (strlen(str) + 1 > str_max_len) {
		printf("Error: '%s' is too long for this poor, limited parser...\n", str);
		return false;
	}
	strcpy(str_copy, str);

	// Count the number of ints in the string.
	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		array_len++;
		token = strtok(NULL, ",");
	}

	if (array_len == 0) {
		printf("Error: '%s' seems to be an empty list, which is not supported.\n", str);
		return false;
	}

	// Build the result.
	array = malloc(array_len * sizeof(__u16));
	if (!array) {
		printf("Error: Memory allocation failed. Cannot parse...\n");
		return false;
	}

	strcpy(str_copy, str);

	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		if (!str_to_u16(str, &array[array_len], 0, MAX_PORT))
			return false; // Error msg already printed.
		array_len++;
		token = strtok(NULL, ",");
	}

	// Finish.
	*array_out = array;
	*array_len_out = array_len;
	return true;
}

// TODO (later) Do something to join these three functions...
bool str_to_addr4_port(const char *str, struct ipv4_tuple_address *addr_out)
{
	const char *FORMAT = "<IPv4 address>#<port> (eg. 10.20.30.40#50)";
	const int STR_MAX_LEN = INET_ADDRSTRLEN + 1 + 5; // [addr + null chara] + # + port
	char str_copy[STR_MAX_LEN]; // strtok corrupts the string, so we'll be using this copy instead.
	char *token;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		printf("Error: '%s' is too long for this poor, limited parser...\n", str);
		return false;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token || !str_to_addr4(token, &addr_out->address)) {
		printf("Error: Cannot parse '%s' as a %s.\n", str, FORMAT);
		return false;
	}

	token = strtok(NULL, "#");
	if (!token) {
		printf("Error: '%s' does not seem to contain a port (format: %s).\n", str, FORMAT);
		return false;
	}
	if (!str_to_u16(token, &addr_out->l4_id, 0, MAX_PORT))
		return false; // Error msg already printed.

	return true;
}

bool str_to_addr6_port(const char *str, struct ipv6_tuple_address *addr_out)
{
	const char *FORMAT = "<IPv6 address>#<port> (eg. 64:ff9b::#96)";
	const int STR_MAX_LEN = INET6_ADDRSTRLEN + 1 + 5; // [addr + null chara] + # + port
	char str_copy[STR_MAX_LEN]; // strtok corrupts the string, so we'll be using this copy instead.
	char *token;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		printf("Error: '%s' is too long for this poor, limited parser...\n", str);
		return false;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token || !str_to_addr6(token, &addr_out->address)) {
		printf("Error: Cannot parse '%s' as a %s.\n", str, FORMAT);
		return false;
	}

	token = strtok(NULL, "#");
	if (!token) {
		printf("Error: '%s' does not seem to contain a port (format: %s).\n", str, FORMAT);
		return false;
	}
	if (!str_to_u16(token, &addr_out->l4_id, 0, MAX_PORT))
		return false; // Error msg already printed.

	return true;
}

bool str_to_prefix(const char *str, struct ipv6_prefix *prefix_out)
{
	const char *FORMAT = "<IPv6 address>/<length> (eg. 64:ff9b::/96)";
	const int str_max_len = INET6_ADDRSTRLEN + 1 + 3; // [addr + null chara] + / + prefix len
	char str_copy[str_max_len]; // strtok corrupts the string, so we'll be using this copy instead.
	char *token;

	if (strlen(str) + 1 > str_max_len) {
		printf("Error: '%s' is too long for this poor, limited parser...\n", str);
		return false;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token || !str_to_addr6(token, &prefix_out->address)) {
		printf("Error: Cannot parse '%s' as a %s.\n", str, FORMAT);
		return false;
	}

	token = strtok(NULL, "/");
	if (!token) {
		printf("Error: '%s' does not seem to contain a mask (format: %s).\n", str, FORMAT);
		return false;
	}
	if (!str_to_u8(token, &prefix_out->len, 0, 128))
		return false; // Error msg already printed.

	return true;
}
