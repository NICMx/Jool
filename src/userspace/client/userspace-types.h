#ifndef INCLUDE_NAT64_USR_TYPES_H_
#define INCLUDE_NAT64_USR_TYPES_H_

#include <stdbool.h>

static inline bool show_csv_header(bool no_headers, bool csv)
{
	return !no_headers && csv;
}

static inline bool show_footer(bool no_headers, bool csv)
{
	return !no_headers && !csv;
}

#endif /* INCLUDE_NAT64_USR_TYPES_H_ */
