#ifndef SRC_COMMON_STATS_H_
#define SRC_COMMON_STATS_H_

typedef unsigned long jstat;

/*
 * TODO review call hierarchy and make sure every value is only being used once.
 */
typedef enum jstat_type {
	JOOL_MIB_CANNOT_PULL,
	JOOL_MIB_TRUNCATED,
	JOOL_MIB_SHARED6,
	JOOL_MIB_SHARED4,

	JOOL_MIB_UNKNOWN_L3,
	JOOL_MIB_V6_UNKNOWN_L4,
	JOOL_MIB_V4_UNKNOWN_L4,
	JOOL_MIB_V6_UNKNOWN_ICMP,
	JOOL_MIB_V4_UNKNOWN_ICMP,
	JOOL_MIB_V6_UNKNOWN_INNER_L4,
	JOOL_MIB_V4_UNKNOWN_INNER_L4,

	JOOL_MIB_HDR6_VERSION,
	JOOL_MIB_HDR6_PAYLOAD_LEN,

	JOOL_MIB_HDR4_VERSION,
	JOOL_MIB_HDR4_IHL,
	JOOL_MIB_HDR4_TOTAL_LEN,

	JOOL_MIB_INNER_FRAG6,
	JOOL_MIB_2X_INNER6,
	JOOL_MIB_FRAGMENTED_ICMP6,

	JOOL_MIB_INNER_FRAG4,
	JOOL_MIB_2X_INNER4,
	JOOL_MIB_FRAGMENTED_ICMP4,

	JOOL_MIB_MEMLEAK64,
	JOOL_MIB_MEMLEAK46,

	/* F & U */
	JOOL_MIB_HAIRPIN_LOOP,
	JOOL_MIB_DST6,
	JOOL_MIB_DST4,
	JOOL_MIB_NO_BIB,
	JOOL_MIB_ADF,
	JOOL_MIB_SHASH_INIT,
	JOOL_MIB_SHASH_UPDATE,
	JOOL_MIB_SHASH_DIGEST,
	JOOL_MIB_PING_PROHIBITED,
	JOOL_MIB_POOL4_EXHAUSTED,
	JOOL_MIB_BIB_EXISTS,
	JOOL_MIB_EXTERNAL_SYN_PROHIBITED,
	JOOL_MIB_SO1_STORED_PKT,
	JOOL_MIB_SO1_EXISTS,
	JOOL_MIB_SO1_FULL,
	JOOL_MIB_SO2_FULL,
	JOOL_MIB_SO2_STORED_PKT,

	JOOL_MIB_POOL6_NULL,

	JOOL_MIB_MALLOC_FAIL,
	JOOL_MIB_UNKNOWN6,
	JOOL_MIB_UNKNOWN4,

	__JOOL_MIB_MAX
} jstat_type;

struct jool_mib {
	/*
	 * TODO maybe do separate arrays for v4 and v6, since most (all?) values
	 * are mirrored.
	 */
	jstat mibs[__JOOL_MIB_MAX];
};

#endif /* SRC_COMMON_STATS_H_ */
