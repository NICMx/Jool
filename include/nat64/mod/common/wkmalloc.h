#ifndef _JOOL_MOD_KREF_ANALYZER_H
#define _JOOL_MOD_KREF_ANALYZER_H

#include <linux/slab.h>
#include "nat64/common/types.h"

static inline void *__wkmalloc(char *name, size_t size, gfp_t flags)
{
	void *result;

	result = kmalloc(size, flags);
#ifdef KREF_ANALYZER
	if (result)
		log_info("Created object '%s'.", name);
#endif

	return result;
}

/**
 * A "wrapped kernel memory allocation"; a wrapped kmalloc.
 */
#define wkmalloc(type, flags) __wkmalloc(#type, sizeof(type), flags)

static inline void __wkfree(char *name, void *obj)
{
	kfree(obj);
#ifdef KREF_ANALYZER
	log_info("Destroyed object '%s'.", name);
#endif
}

#define wkfree(type, obj) __wkfree(#type, obj)

#endif
