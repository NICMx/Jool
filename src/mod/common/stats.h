#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

#include "common/stats.h"
#include "mod/common/packet.h"

struct jool_stats;

struct jool_stats *jstat_alloc(void);
void jstat_get(struct jool_stats *stats);
void jstat_put(struct jool_stats *stats);

void jstat_inc(struct jool_stats *stats, enum jool_stat_id stat);
void jstat_dec(struct jool_stats *stats, enum jool_stat_id stat);
void jstat_add(struct jool_stats *stats, enum jool_stat_id stat, int addend);

__u64 *jstat_query(struct jool_stats *stats);

#endif /* _JOOL_MOD_STATS_H */
