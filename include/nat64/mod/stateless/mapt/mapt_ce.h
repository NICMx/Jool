#include "nat64/mod/common/rbtree.h"
/* A (NAT44) Network Address and Port Translation (NAPT) [RFC2663]
     function on a MAP CE is extended with support for restricting the
     allowable TCP/UDP ports for a given IPv4 address.  The IPv4
     address and port range used are determined by the MAP provisioning
     process and identical to MAP-E [RFC7597].*/


struct protocol_restricted_ports {

	struct in_addr addressv4;
	__u16 ports_allowed_min;
	__u16 ports_allowed_max;

};

struct tcp_port_restriction_table {

	struct rtrie trie4;
	/**
	 * This one is not RCU-friendly. Touch only while you're holding the
	 * mutex.
	 */
	__u64 count;
	struct kref refcount;
};


struct udp_port_restriction_table {

	struct rtrie trie4;

	/**
	 * This one is not RCU-friendly. Touch only while you're holding the
	 * mutex.
	 */
	__u64 count;
	struct kref refcount;

};
