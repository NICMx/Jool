#ifndef _JOOL_USR_STR_UTILS_H
#define _JOOL_USR_STR_UTILS_H

/**
 * @file
 * Two-liners (since you need to check the return value) for string-to-something
 * else conversions.
 * This is very noisy on the console on purpose because it is only used by the
 * parser of the userspace app's arguments.
 */

#include "nat64/common/str_utils.h"

/** Maximum storable value on a __u8. */
#define MAX_U8 0xFFU
/** Maximum storable value on a __u16. */
#define MAX_U16 0xFFFFU
/** Maximum storable value on a __u32. */
#define MAX_U32 0xFFFFFFFFU
/** Maximum storable value on a __u64. */
#define MAX_U64 0xFFFFFFFFFFFFFFFFU

/**
 * Parses @str as a boolean value, which it then copies to @out.
 */
int str_to_bool(const char *str, __u8 *out);

int validate_int(const char *str);

/**
 * Parses @str" as a number, which it then copies to @out.
 * Refuses to succeed if @out is less than @min or higher than @max.
 */
int str_to_u8(const char *str, __u8 *out, __u8 min, __u8 max);
int str_to_u16(const char *str, __u16 *out, __u16 min, __u16 max);
int str_to_u32(const char *str, __u32 *out, __u32 min, __u32 max);
int str_to_u64(const char *str, __u64 *out, __u64 min, __u64 max);

int str_to_port_range(char *str, struct port_range *range);

/**
 * Parses @str as a comma-separated array of __u16s, which it then copies to
 * @out.
 * It sets @out_len as @out's length in elements (not bytes).
 */
int str_to_u16_array(const char *str, __u16 **out, size_t *out_len);

/**
 * Parses @str as a '#' separated l3-address and l4-identifier, which it then
 * copies to @out".
 */
int str_to_addr4_port(const char *str, struct ipv4_transport_addr *out);
int str_to_addr6_port(const char *str, struct ipv6_transport_addr *out);

/**
 * Parses @str as an IP prefix (<prefix address>/<mask>), which it then copies
 * to @out.
 * If str contains no mask, it will default to @out's maximum sensible mask.
 */
int str_to_prefix6(const char *str, struct ipv6_prefix *out);
int str_to_prefix4(const char *str, struct ipv4_prefix *out);

/**
 * Prints the @millis amount of milliseconds as spreadsheet-friendly format in
 * the console.
 */
void print_time_csv(unsigned int millis);
/**
 * Prints the @millis amount of milliseconds as a fairly human-readable string
 * in the console.
 */
void print_time_friendly(unsigned int millis);

#endif /* _JOOL_COMM_STR_UTILS_H */
