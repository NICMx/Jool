#ifndef SRC_COMMON_GLOBAL_H_
#define SRC_COMMON_GLOBAL_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif
#include "common/config.h"

typedef enum global_type_id {
	GTI_BOOL,
	GTI_NUM8,
	GTI_NUM32,
	GTI_PLATEAUS,
	GTI_PREFIX6,
	GTI_PREFIX4,
	GTI_HAIRPIN_MODE,
} global_type_id;

struct global_field;

typedef void (*print_function)(void *value, bool csv);
typedef int (*parse_function)(struct global_field *field, char *str,
		void *result);
/* This function does not need to validate xlator_type nor type->size. */
typedef int (*validate_function)(struct global_field *field, void *value,
		bool force);

struct global_type {
	global_type_id id;
	const char *name;
	size_t size;
	print_function print;
	parse_function parse;
	validate_function validate;
};

struct global_field {
	char *name; /* This being NULL means the end of the array. */
	struct global_type *type;
	const char *doc;
	size_t offset;
	xlator_type xt;
	__u64 min;
	__u64 max;
	print_function print; /* Overrides type->print. */
	validate_function validate; /* Overrides type->validate. */
};

void get_global_fields(struct global_field **fields, unsigned int *len);
long int global_field_index(struct global_field *field);

#endif /* SRC_COMMON_GLOBAL_H_ */
