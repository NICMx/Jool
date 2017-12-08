#ifndef _JOOL_COMMON_STR_UTILS_H
#define _JOOL_COMMON_STR_UTILS_H

/**
 * @file
 * String-to-address conversion, intended to unify the API for both kernel and userspace.
 */

#include "types.h"

/**
 * Converts "str" to a IPv4 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in4_pton() we don't want.
 */
int str_to_addr4(const char *str, struct in_addr *result);
/**
 * Converts "str" to a IPv6 address. Stores the result in "result".
 *
 * Useful mainly in code common to kernelspace and userspace, since their conversion functions
 * differ, but meant to be used everywhere to strip the parameters from in6_pton() we don't want.
 */
int str_to_addr6(const char *str, struct in6_addr *result);

/**
 * Returns a string version of "proto".
 */
const char *l3proto_to_string(l3_protocol proto);

/**
 * Returns a string version of "proto".
 */
const char *l4proto_to_string(l4_protocol proto);

#endif /* _JOOL_COMMON_STR_UTILS_H */
