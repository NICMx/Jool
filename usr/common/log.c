#include "nat64/usr/log.h"
#include <string.h>

void log_perror(char *prefix, int error)
{
	char buffer[256];

	if (strerror_r(error, buffer, sizeof(buffer))) {
		log_err("%s: %d", prefix, error);
		log_err("(Sorry. I tried to stringify that but it didn't work.)");
	} else {
		log_err("%s: %s", prefix, buffer);
	}
}
