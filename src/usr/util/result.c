#include "result.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct jool_result result_success(void)
{
	struct jool_result result;

	result.error = 0;
	result.msg = NULL;
	result.flags = JRF_INITIALIZED;

	return result;
}

/**
 * @error: Error code the function died with. Usually errno.
 * @prefix: Name of the function that errored.
 */
struct jool_result result_from_errno(int error_code, char const *function)
{
	size_t function_len;
	static char const *const SEPARATOR = "() error: ";
	size_t separator_len;
	char *suffix;
	struct jool_result result;

	if (error_code == 0)
		error_code = -EINVAL; /* We know there's an error */

	function_len = strlen(function);
	separator_len = strlen(SEPARATOR);
	suffix = strerror(error_code);

	result.error = error_code;
	result.msg = malloc(function_len + separator_len + strlen(suffix) + 1);
	if (!result.msg) {
		result.msg = suffix;
		result.flags = JRF_INITIALIZED;
	} else {
		strcpy(result.msg, function);
		strcpy(result.msg + function_len, SEPARATOR);
		strcpy(result.msg + function_len + separator_len, suffix);
		result.flags = JRF_INITIALIZED | JRF_MSG_IN_HEAP;
	}

	return result;
}

struct jool_result result_from_error(int error_code, char const *msg, ...)
{
	static const size_t MAX_STR_LEN = 1024;
	struct jool_result result;
	va_list args;

	if (error_code == 0)
		error_code = -EINVAL; /* We know there's an error */

	/* TODO (NOW) handle caller wants us to fail silently. */

	result.error = error_code;
	result.flags = JRF_INITIALIZED | JRF_MSG_IN_HEAP;
	result.msg = malloc(MAX_STR_LEN);
	if (!result.msg) {
		result.msg = strerror(error_code); /* "Best effort" */
		result.flags = JRF_INITIALIZED;
		return result;
	}
	va_start(args, msg);
	vsnprintf(result.msg, MAX_STR_LEN, msg, args);
	va_end(args);

	return result;
}

struct jool_result result_from_enomem(void)
{
	struct jool_result result;
	result.error = -ENOMEM;
	result.msg = strerror(-ENOMEM);
	result.flags = JRF_INITIALIZED;
	return result;
}

void result_cleanup(struct jool_result *result)
{
	if (result->flags & JRF_MSG_IN_HEAP)
		free(result->msg);
}
