#include "module-stats.h"

#include <linux/kref.h>
#include <net/snmp.h>
#include <net/ip.h> /* snmp_get_cpu_field */

#include "wkmalloc.h"

struct jool_stats {
	DEFINE_SNMP_STAT(struct jool_mib, mib);
	struct kref refcounter;
};

struct jool_stats *jstat_alloc(void)
{
	struct jool_stats *result;

	result = wkmalloc(struct jool_stats, GFP_KERNEL);
	if (!result)
		return NULL;

	result->mib = alloc_percpu(struct jool_mib);
	if (!result->mib) {
		wkfree(struct jool_stats, result);
		return NULL;
	}

	kref_init(&result->refcounter);
	return result;
}

void jstat_get(struct jool_stats *stats)
{
	kref_get(&stats->refcounter);
}

static void release(struct kref *refcounter)
{
	struct jool_stats *stats;
	stats = container_of(refcounter, struct jool_stats, refcounter);
	free_percpu(stats->mib);
	wkfree(struct jool_stats, stats);
}

void jstat_put(struct jool_stats *stats)
{
	kref_put(&stats->refcounter, release);
}

void jstat_add(struct jool_stats *stats, jstat_type type, jstat addend)
{
	SNMP_ADD_STATS64(stats->mib, type, addend);
}

void jstat_inc(struct jool_stats *stats, jstat_type type)
{
	SNMP_INC_STATS64(stats->mib, type);
}

void jstat_query(struct jool_stats *stats, struct jool_mib *result)
{
	unsigned int cpu, i;

	memset(result, 0, sizeof(*result));

	/* Reference: snmp_get_cpu_field_batch() */
	for_each_possible_cpu(cpu) {
		for (i = 0; i < __JOOL_MIB_MAX; i++)
			result->mibs[i] += snmp_get_cpu_field(stats->mib, cpu, i);
	}
}
