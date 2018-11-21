#ifndef SRC_USR_COMMON_COMMON_GLOBAL_H_
#define SRC_USR_COMMON_COMMON_GLOBAL_H_

#include "common/common-global.h"

void print_bool(void *value, bool csv);
void print_u8(void *value, bool csv);
void print_u32(void *value, bool csv);
void print_timeout(void *value, bool csv);
void print_plateaus(void *value, bool csv);
void print_prefix6(void *value, bool csv);
void print_prefix4(void *value, bool csv);
void print_hairpin_mode(void *value, bool csv);
void print_fargs(void *value, bool csv);

int parse_bool(struct global_field *field, char *str, void *result);
int parse_u8(struct global_field *field, char *str, void *result);
int parse_u32(struct global_field *field, char *str, void *result);
int parse_timeout(struct global_field *field, char *str, void *result);
int parse_plateaus(struct global_field *field, char *str, void *result);
int parse_prefix6(struct global_field *field, char *str, void *result);
int parse_prefix4(struct global_field *field, char *str, void *result);
int parse_hairpin_mode(struct global_field *field, char *str, void *result);

#define validate_u8 NULL
#define validate_u32 NULL
#define validate_pool6 NULL
#define validate_plateaus NULL
#define validate_prefix6 NULL
#define validate_prefix4 NULL
#define validate_prefix6791v4 NULL
#define validate_hairpin_mode NULL

#endif /* SRC_USR_COMMON_COMMON_GLOBAL_H_ */
