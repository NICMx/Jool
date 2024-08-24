#include "usr/argp/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

void pr_warn(const char *format, ...)
{
	va_list args;

	fprintf(stderr, "Warning: ");

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, "\n");
}

void pr_err(const char *format, ...)
{
	va_list args;

	fprintf(stderr, "Error: ");

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, "\n");
}

int pr_result(struct jool_result *result)
{
	int error = result->error;

	if (error)
		pr_err("%s", result->msg);

	result_cleanup(result);
	return error;
}

int pr_result_syslog(struct jool_result *result)
{
	int error = result->error;

	if (error)
		syslog(LOG_ERR, "%s", result->msg);

	result_cleanup(result);
	return error;
}

void pr_perror(char *prefix, int error)
{
	char buffer[256];

	if (strerror_r(error, buffer, sizeof(buffer))) {
		syslog(LOG_ERR, "%s: %d", prefix, error);
		syslog(LOG_ERR, "(Sorry. I tried to stringify that but it didn't work.)");
	} else {
		syslog(LOG_ERR, "%s: %s", prefix, buffer);
	}
}
