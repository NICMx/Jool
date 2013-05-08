#include <linux/random.h>

/**
 * @file
 * I noticed the less I call the kernel's get_random_bytes() function, the better. If I need 64
 * kilobytes worth of random, calling it once is fastest, 64 times for 1024 bytes each is fast,
 * and 65536 times for one byte each is kernel-freezing.
 * Thing is, I hate kmallocs due to their unreliability.
 * get_random_bytes() seems to beg for a buffer, so here it is.
 */

u32 get_random_u32(void);
