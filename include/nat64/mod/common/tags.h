#ifndef _JOOL_MOD_TAGS_H
#define _JOOL_MOD_TAGS_H

/**
 * @file
 * The macros defined in this file do nothing whatsoever. They only exist to
 * help me review the code.
 *
 * Feel free to purge this if the code leaves my care.
 */

/**
 * Tagged function doesn't need care about concurrence at all.
 *
 * - Usable anywhere.
 * - GFP_KERNEL is not allowed.
 *
 * Can only call fellow RCUTAG_FREE functions.
 */
#define RCUTAG_FREE

/**
 * Tagged function is a RCU reader.
 *
 * - Usable during packet processing.
 * - GFP_KERNEL is not allowed.
 *
 * Can call fellow RCUTAG_PKT and RCUTAG_FREE functions.
 */
#define RCUTAG_PKT

/**
 * Tagged function has to be used in process context. Typically, these are
 * userspace request handlers.
 *
 * - Cannot be used during packet processing.
 * - GFP_KERNEL is allowed.
 *
 * Can call anything except RCUTAG_INIT.
 */
#define RCUTAG_USR

/**
 * Marked function always runs in isolation. These also don't have to worry
 * about concurrence.
 *
 * - Must be called during module load/unload only.
 * - GFP_KERNEL is allowed.
 *
 * Can call anything.
 */
#define RCUTAG_INIT

#endif /* _JOOL_MOD_TAGS_H */
