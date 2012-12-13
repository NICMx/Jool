#ifndef NF_NAT64_CONFIG_H_
#define NF_NAT64_CONFIG_H_


#ifdef _USER_SPACE_
	#include <netinet/in.h>
	#include <stdbool.h>
	#include <asm/types.h>
#else
	#include <linux/in.h>
	#include <linux/in6.h>

#endif

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES (Configuration)
////////////////////////////////////////////////////////////////////////

// IPv6:
#define IPV6_DEF_PREFIX			"64:ff9b::"
#define IPV6_DEF_MASKBITS   	96
#define IPV6_DEF_MASKBITS_MAX   96
#define IPV6_DEF_MASKBITS_MIN   32

// IPv4:
#define IPV4_DEF_POOL_NET	"192.168.2.0"
#define IPV4_DEF_POOL_NET_MASK_BITS   24
//
#define IPV4_DEF_POOL_FIRST "192.168.2.1"
#define IPV4_DEF_POOL_LAST  "192.168.2.254"

#define BIB_MASK (1<<0)
#define SESSION_MASK (1<<1)
#define IPV6_MASK (1<<2)
#define IPV4_MASK (1<<3)
#define HAIR_MASK (1<<4)
#define PHR_MASK (1<<5)
#define PTR_MASK (1<<6)
#define OIPV6_MASK (1<<7)
#define OIPV4_MASK (1<<8)
#define IPV4_TRAFFIC_MASK (1<<9)
#define DF_ALWAYS_MASK (1<<10)
#define GEN_IPV4_MASK (1<<11)
#define IMP_MTU_FAIL_MASK (1<<12)
#define IPV6_NEXTHOP_MASK (1<<13)
#define IPV4_NEXTHOP_MASK (1<<14)
#define MTU_PLATEAUS_MASK (1<<15)
#define MTU_PLATEAU_COUNT_MASK (1<<16)
#define ADDRESS_DEPENDENT_FILTER_MASK (1<<17)
#define FILTER_INFO_MASK (1<<18)
#define DROP_TCP_MASK (1<<19)

/**
 * Struct to handle valid IPv6 prefixes specified as configuration parameters.
 */
struct ipv6_prefixes 
{
	struct in6_addr addr;	///< IPv6 prefix
	unsigned char maskbits;	///< Network mask in CIDR format.
};

/**
 * This holds the entire running and valid configuration.
 */
struct config_struct
{

	//// Operational:
	unsigned char address_dependent_filtering;	/**< Use Address-Dependent Filtering? */
	unsigned char filter_informational_icmpv6;	/**< Filter ICMPv6 Informational packets */
	unsigned char drop_externally_initiated_tcp_connections;/**< Drop externally initiated TCP connections? (IPv4 initiated) */
	
    //// IPv4:
    struct in_addr ipv4_pool_net; 				/**< IPv4 Pool network address. */
	unsigned char  ipv4_pool_net_mask_bits; 	/**< IPv4 Pool network address, in CIDR format. */
	struct in_addr ipv4_pool_range_first;		/**< IPv4 Pool first valid address. */
	struct in_addr ipv4_pool_range_last;		/**< IPv4 Pool last valid address. */
    //
   
    //// IPv6:
	struct ipv6_prefixes **ipv6_net_prefixes;		/**< Array of valid prefixes. */
	unsigned char 		   ipv6_net_prefixes_qty;	/**< Length of the array. */
    //

	u_int8_t	hairpinning_mode; 

};

struct route_struct 
{
    //// IPv4:
	struct in_addr ipv4_src_address;
    struct in_addr ipv4_dst_address;
    //
    unsigned short ipv4_src_port_or_id;
    unsigned short ipv4_dst_port_or_id;
    //
    //// IPv6:
    struct in6_addr ipv6_src_address;
    struct in6_addr ipv6_dst_address;
    //
    unsigned short  ipv6_src_port_or_id;
    unsigned short  ipv6_dst_port_or_id; 

    u_int8_t protocol;
};

struct configuration
{

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

struct manconf_struct {
	unsigned short mode; /// Which mode we are working with.
	unsigned short operation; /// Which operation are we going to perform.
	__u64 submode;

	union {
		struct route_struct rs;
		struct config_struct cs;
		struct configuration cc;
	} us;
};

struct answer_struct {
	unsigned short mode; /// Which mode we are working with.
	unsigned short operation; /// Which operation are we going to perform.
	__u64 submode;

	__u32 array_quantity;

};

extern struct configuration config;
extern struct config_struct cs;

bool nat64_config_init(void);
void nat64_config_destroy(void);

int update_nat_config(struct manconf_struct *mst, struct answer_struct **as, __u32 *as_len);

#endif /* NF_NAT64_CONFIG_H_ */
