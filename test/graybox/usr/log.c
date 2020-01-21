#include "log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

int pr_err(const char *format, ...)
{
	va_list args;

	fprintf(stderr, "Error: ");

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, "\n");

	return -EINVAL;
}

int pr_enomem(void)
{
	pr_err("Out of memory.");
	return -ENOMEM;
}
