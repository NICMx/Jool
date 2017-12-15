#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

#include "stats.h"

struct jool_stats;

struct jool_stats *jstat_alloc(void);
void jstat_get(struct jool_stats *stats);
void jstat_put(struct jool_stats *stats);

void jstat_add(struct jool_stats *stats, jstat_type type, jstat addend);
void jstat_inc(struct jool_stats *stats, jstat_type type);

void jstat_query(struct jool_stats *stats, struct jool_mib *result);

#endif /* _JOOL_MOD_STATS_H */
