#include "usr/argp/log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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

int pr_enomem(void)
{
	pr_err("%s", strerror(-ENOMEM));
	return -ENOMEM;
}
