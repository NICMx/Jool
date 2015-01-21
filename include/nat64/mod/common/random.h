#ifndef _JOOL_MOD_RANDOM_H
#define _JOOL_MOD_RANDOM_H

/**
 * @file
 * I noticed the less I call the kernel's get_random_bytes() function, the better. If I need 64
 * kilobytes worth of random, calling it once is fastest, 64 times for 1024 bytes each is fast,
 * and 65536 times for one byte each is kernel-freezing.
 * Thing is, I hate kmallocs due to their unreliability.
 * get_random_bytes() seems to beg for a buffer, so here it is.
 *
 * TODO (issue36) this module should probably go away when we fix #36.
 * This is because nothing else in the code requires large amounts of random numbers at once.
 *
 * @author Alberto Leiva
 */

#include <linux/random.h>

/**
 * Returns 32 random bits in the form of a 4-byte unsigned integer.
 */
u32 get_random_u32(void);

#endif /* _JOOL_MOD_RANDOM_H */
