#ifndef NF_NAT64_CONFIG_H_
#define NF_NAT64_CONFIG_H_

#include <linux/in.h>


struct configuration
{
	struct in_addr ipv4_pool_range_first;
	struct in_addr ipv4_pool_range_last;

	/**
	 * The user's reserved head room in bytes. Default should be 0.
	 * Can be negative, if the user wants to compensate for the LL_MAX_HEADER constant.
	 * (LL_MAX_HEADER = the kernel's reserved head room + l2 header's length.)
	 */
	__u16 packet_head_room;
	/** I suggest default = 32 bytes. */
	__u16 packet_tail_room;

	bool override_ipv6_traffic_class;
	/** Default should be false. */
	bool override_ipv4_traffic_class;
	__u8 ipv4_traffic_class;
	/** Default should be true. */
	bool df_always_set;

	/** Default should be false. */
	bool generate_ipv4_id;

	/** Default should be true; in fact I don't see why anyone would want it to be false. */
	bool improve_mtu_failure_rate;
	// TODO (info) there should probably be a way to compute these two values by ourselves.
	__u16 ipv6_nexthop_mtu;
	__u16 ipv4_nexthop_mtu;

	/** Default values are { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }. */
	__u16 *mtu_plateaus;
	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;
};

extern struct configuration config;

bool nat64_load_default_config(void);


#endif /* NF_NAT64_CONFIG_H_ */
