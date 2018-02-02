#ifndef INCLUDE_NAT64_USR_TYPES_H_
#define INCLUDE_NAT64_USR_TYPES_H_

#include <stdbool.h>

typedef enum display_flags {
	DF_CSV_FORMAT = 1 << 4,
	DF_NO_HEADERS = 1 << 5,
	DF_NUMERIC_HOSTNAME = 1 << 6,
} display_flags;

static inline bool show_csv_header(display_flags flags)
{
	return !(flags & DF_NO_HEADERS) && (flags & DF_CSV_FORMAT);
}

static inline bool show_footer(display_flags flags)
{
	return !(flags & DF_NO_HEADERS) && !(flags & DF_CSV_FORMAT);
}

#endif /* INCLUDE_NAT64_USR_TYPES_H_ */
