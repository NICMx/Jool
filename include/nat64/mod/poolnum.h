#ifndef _JOOL_MOD_POOLNUM_H
#define _JOOL_MOD_POOLNUM_H

#include <linux/types.h>


/**
 * A container of numbers other code can borrow.
 */
struct poolnum {
	/**
	 * Container of the numbers in this pool.
	 * Slots in and ahead of the "next"th slot contain numbers that haven't been borrowed.
	 * Slots between "next" and "returned" contain plain garbage.
	 * Slots behind "returned" are numbers that were once borrowed and recently returned.
	 */
	u16 *array;
	/** Length of "array". */
	u32 count;
	/** The index of the next value that will be retrieved, if the pool still has values. */
	u32 next;
	/** The slot where the next returned value will be placed in, but only if "next" is ahead. */
	u32 returned;
	/**
	 * Whether "next" is ahead of "returned". If they point to the same slot, this will tell whether
	 * the pool is exhausted or if nothing has been retrieved.
	 * ("returned" is logically never considered to be ahead of "next", even if the latter wraps
	 * around.)
	 */
	bool next_is_ahead;
};

int poolnum_init(struct poolnum *pool, u16 min, u16 max, u16 step);
void poolnum_destroy(struct poolnum *pool);

int poolnum_get_any(struct poolnum *pool, u16 *result);
int poolnum_get(struct poolnum *pool, u16 value);
int poolnum_return(struct poolnum *pool, u16 value);

/**
 * Returns whether the pool has all of its values (ie. nobody has requested anything, or everyone
 * has returned everything).
 */
bool poolnum_is_full(struct poolnum *pool);
/**
 * Returns whether the pool has no values (ie. everyting has been borrowed).
 */
bool poolnum_is_empty(struct poolnum *pool);

#endif /* _JOOL_MOD_POOLNUM_H */
