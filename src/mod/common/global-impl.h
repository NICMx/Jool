#ifndef SRC_MOD_COMMON_COMMON_GLOBAL_H_
#define SRC_MOD_COMMON_COMMON_GLOBAL_H_

#include "common/common-global.h"

#define print_bool NULL
#define print_u8 NULL
#define print_u32 NULL
#define print_timeout NULL
#define print_plateaus NULL
#define print_prefix6 NULL
#define print_prefix4 NULL
#define print_hairpin_mode NULL
#define print_fargs NULL

#define parse_bool NULL
#define parse_u8 NULL
#define parse_u32 NULL
#define parse_timeout NULL
#define parse_plateaus NULL
#define parse_prefix6 NULL
#define parse_prefix4 NULL
#define parse_hairpin_mode NULL

int validate_u8(struct global_field *field, void *value, bool force);
int validate_u32(struct global_field *field, void *value, bool force);
int validate_pool6(struct global_field *field, void *value, bool force);
int validate_plateaus(struct global_field *field, void *value, bool force);
int validate_prefix6(struct global_field *field, void *value, bool force);
int validate_prefix4(struct global_field *field, void *value, bool force);
int validate_prefix6791v4(struct global_field *field, void *value, bool force);
int validate_hairpin_mode(struct global_field *field, void *value, bool force);

#endif /* SRC_MOD_COMMON_COMMON_GLOBAL_H_ */
