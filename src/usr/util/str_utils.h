#ifndef _JOOL_USR_STR_UTILS_H
#define _JOOL_USR_STR_UTILS_H

/**
 * @file
 * Two-liners (since you need to check the return value) for string-to-something
 * else conversions.
 * This is very noisy on the console on purpose because it is only used by the
 * parser of the userspace app's arguments.
 */

#include "common/str_utils.h"

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

int str_to_timeout(const char *str, __u32 *result, __u32 min, __u32 max);
int str_to_port_range(char *str, struct port_range *range);

/**
 * Parses @str as a comma-separated array of __u16s, which it then copies to
 * @result.
 *
 * @result is assumed to length PLATEAUS_MAX elements. The actual length is
 * going to be copied to @count.
 */
int str_to_plateaus_array(const char *str, __u16 *result, __u16 *count);

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

#ifndef __KERNEL__
#include <stdio.h>
/**
 * Prints the @millis amount of milliseconds in @stream.
 * The format is "HH:MM:SS" or "HH:MM:SS.mmm".
 */
void print_timeout_hhmmss(FILE *stream, unsigned int millis);
#endif

#define STR_EQUAL(s1, s2) (strcmp(s1, s2) == 0)

#endif /* _JOOL_COMM_STR_UTILS_H */
