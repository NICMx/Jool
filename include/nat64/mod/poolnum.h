#ifndef _NF_NAT64_POOLNUM_H
#define _NF_NAT64_POOLNUM_H

#include <linux/types.h>

struct poolnum {
	u16 *array;
	u32 count;
	/** The index of the next value that will be retrieved, if the pool still has values. */
	u32 next;
	/** The slot where the next returned value will be placed in, but only if next is ahead. */
	u32 returned;
	/**
	 * Whether next is ahead of returned. If they point to the same slot, this will tell whether
	 * the pool is exhausted or if nothing has been retrieved.
	 */
	bool next_is_ahead;
};

int poolnum_init(struct poolnum *pool, u16 min, u16 max, u16 step);
void poolnum_destroy(struct poolnum *pool);

int poolnum_get_any(struct poolnum *pool, u16 *result);
bool poolnum_get(struct poolnum *pool, u16 value);
int poolnum_return(struct poolnum *pool, u16 value);

#endif /* _NF_NAT64_POOLNUM_H */
