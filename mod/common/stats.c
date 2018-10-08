#include "nat64/mod/common/stats.h"

/*
 * This module is under construction.
 * I decided to leave it out of the release candidate because I'm running out
 * of time.
 * To be implemented in Jool 3.6.1 probably.
 */

struct jool_stats {
	int junk;
};

struct jool_stats *jstat_alloc(void)
{
	return NULL;
}

void jstat_get(struct jool_stats *stats)
{
	/* Do nothing for now. */
}

void jstat_put(struct jool_stats *stats)
{
	/* Do nothing for now. */
}

void jstat_inc(struct jool_stats *stats, int field)
{
	/* Do nothing for now. */
}
