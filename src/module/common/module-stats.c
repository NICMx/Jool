#include "module-stats.h"
#include <net/snmp.h>
#include <net/ip.h> /* snmp_get_cpu_field_batch */

struct jool_mib __percpu *jstat_alloc(void)
{
	return alloc_percpu(struct jool_mib);
}

void jstat_free(struct jool_mib __percpu *stats)
{
	free_percpu(stats);
}

void jstat_add(struct jool_mib __percpu *stats, jstat_type type, jstat addend)
{
	SNMP_ADD_STATS64(stats, type, addend);
}

void jstat_inc(struct jool_mib __percpu *stats, jstat_type type)
{
	SNMP_INC_STATS64(stats, type);
}

void jstat_query(struct jool_mib __percpu *stats, struct jool_mib *result)
{
	unsigned int cpu, i;

	memset(result, 0, sizeof(*result));

	/* Reference: snmp_get_cpu_field_batch() */
	for_each_possible_cpu(cpu) {
		for (i = 0; i < __JOOL_MIB_MAX; i++)
			result->mibs[i] += snmp_get_cpu_field(stats, cpu, i);
	}
}
