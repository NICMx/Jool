#ifndef _JOOL_MOD_MAPT_H
#define _JOOL_MOD_MAPT_H

#include "nat64/common/types.h"

struct mapping_rule {

	struct ipv6_prefix v6_prefix;
	struct ipv4_prefix v4_prefix;
	__u16 port_range_min;
	__u16 port_range_max;

	/*
	 * Tells us the length of the embedded address in bits.
	 *
	 * The sum of the ipv6_prefix length and the value of this field
	 * must be less or equal than the  End-user IPv6 prefix length.
	 */
	__u8 embedded_address_length;

};


struct mapping_rule_table {

	struct rtrie trie6;
	struct rtrie trie4;
	/**
	 * This one is not RCU-friendly. Touch only while you're holding the
	 * mutex.
	 */
	__u64 count;
	struct kref refcount;
};

struct enduser_prefix6_table {

	struct rtrie trie6;
	/**
	 * This one is not RCU-friendly. Touch only while you're holding the
	 * mutex.
	*/
	__u64 count;
	struct kref refcount;

};

/**
 *  epu6_mr_relation stands for enduser-prefix6-maprule-relation-table
 */

struct eup6_mr_relation_entry {

	struct mapping_rule *rule;
	struct ipv6_prefix *enduser_prefix;

	struct rb_node relation_hook;
	struct kref refcount;
};

struct eup6_mr_relation_table {

	struct rb_root *relation_entry;

	__u64 count;

	spinlock_t lock;
	bool log_changes;
};

#endif
