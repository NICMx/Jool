#ifndef _JOOL_USR_STR_UTILS_H
#define _JOOL_USR_STR_UTILS_H

/**
 * @file
 * Two-liners (since you need to check the return value) for string-to-something else conversions.
 * This is only used by the parser of the user's arguments, so it's very noisy on the console on
 * purpose.
 *
 * @author Alberto Leiva
 */

#include "nat64/comm/str_utils.h"

/** Maximum storable value on a __u8. */
#define MAX_U8 0xFF
/** Maximum storable value on a __u16. */
#define MAX_U16 0xFFFF
/** Maximum storable value on a __u32. */
#define MAX_U32 0xFFFFFFFF
/** Maximum storable value on a __u64. */
#define MAX_U64 0xFFFFFFFFFFFFFFFF

/**
 * Parses "str" as a boolean value, which it then copies to "out".
 */
int str_to_bool(const char *str, __u8 *out);

/**
 * @{
 * Parses "str" as a number, which it then copies to "out".
 * Refuses to succeed if "out" is less than "min" or higher than "max".
 */
int str_to_u8(const char *str, __u8 *out, __u8 min, __u8 max);
int str_to_u16(const char *str, __u16 *out, __u16 min, __u16 max);
int str_to_u64(const char *str, __u64 *out, __u64 min, __u64 max);
/**
 * @}
 */

/**
 * Parses "str" as a comma-separated array of __u16s, which it then copies to "out".
 * It sets "out_len" as "out"'s length in elements (not bytes).
 */
int str_to_u16_array(const char *str, __u16 **out, size_t *out_len);

/**
 * @{
 * Parses "str" as a '#' separated l3-address and l4-identifier, which it then copies to "out".
 */
int str_to_addr4_port(const char *str, struct ipv4_tuple_address *out);
int str_to_addr6_port(const char *str, struct ipv6_tuple_address *out);
/**
 * @}
 */

/**
 * Parses "str" as a IPv6 prefix (<prefix address>/<mask>), which it then copies to "out".
 */
int str_to_prefix(const char *str, struct ipv6_prefix *out);

/**
 * Prints the "millis" amount of milliseconds as spreadsheet-friendly format in the console.
 */
void print_time_csv(__u64 millis);

/**
 * Prints the "millis" amount of milliseconds as a fairly human-readable string in the console.
 */
void print_time_friendly(__u64 millis);

#endif /* _JOOL_COMM_STR_UTILS_H */

