#ifndef _JOOL_MOD_STATS_H
#define _JOOL_MOD_STATS_H

#include "stats.h"
#include <linux/percpu.h>

struct jool_mib __percpu *jstat_alloc(void);
void jstat_free(struct jool_mib __percpu *stats);

void jstat_add(struct jool_mib __percpu *stats, jstat_type type, jstat addend);
void jstat_inc(struct jool_mib __percpu *stats, jstat_type type);

void jstat_query(struct jool_mib __percpu *all_stats, struct jool_mib *result);

#endif /* _JOOL_MOD_STATS_H */
