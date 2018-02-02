#ifndef SRC_COMMON_GLOBAL_H_
#define SRC_COMMON_GLOBAL_H_

#include <stddef.h>
#include "constants.h"
#include "nl-protocol.h"

typedef enum global_type_id {
	GTI_BOOL,
	GTI_NUM8,
	GTI_NUM16,
	GTI_NUM32,
	GTI_PLATEAUS,
	GTI_PREFIX6,
	GTI_PREFIX4,
} global_type_id;

struct global_field;

typedef void (*print_function)(void *value);
typedef int (*parse_function)(struct global_field *field, char *str,
		void *result);

struct global_type {
	global_type_id id;
	const char *name;
	size_t size;
	print_function print;
	parse_function parse;
};

struct global_field {
	/* This being NULL means the end of the array. */
	const char *name;
	struct global_type *type;
	const char *doc;
	size_t offset;
	__u64 min;
	__u64 max;
	print_function print;
};

void get_global_fields(struct global_field **fields, unsigned int *len);

#endif /* SRC_COMMON_GLOBAL_H_ */
