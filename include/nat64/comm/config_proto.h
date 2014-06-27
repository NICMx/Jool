#ifndef _JOOL_COMM_CONFIG_PROTO_H
#define _JOOL_COMM_CONFIG_PROTO_H

/**
 * @file
 * Elements visible to both the kernel module and the userspace application, and which they use to
 * communicate with each other.
 *
 * TODO (error) some fields here don't have fixed size data types. That will suck when users run
 * userspaces on top of kernels of dissimilar bittage.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include <linux/types.h>
#include "nat64/comm/types.h"


/**
 * ID of Netlink messages Jool listens to.
 * This value was chosen at random, if I remember correctly.
 */
#define MSG_TYPE_JOOL (0x10 + 2)

/**
 * ID of messages intended to return configuration to userspace.
 * ("set config" is intended to be read from the kernel's perspective).
 * This exists as an attempt to match Netlink's conventions; Jool doesn't really care about it.
 */
#define MSG_SETCFG		0x11
/**
 * ID of messages intended to update configuration.
 * ("get config" is intended to be read from the kernel's perspective).
 * This exists as an attempt to match Netlink's conventions; Jool doesn't really care about it.
 *
 * TODO (fine) Looks like nobody is using this. Jool's alignment to Netlink's conventions should
 * probably be rethought.
 */
#define MSG_GETCFG		0x12

enum config_mode {
	/** The current message is talking about the IPv6 pool. */
	MODE_POOL6 = 1,
	/** The current message is talking about the IPv4 pool. */
	MODE_POOL4,
	/** The current message is talking about the Binding Information Bases. */
	MODE_BIB,
	/** The current message is talking about the session tables. */
	MODE_SESSION,
	/** The current message is talking about the Filtering module. */
	MODE_FILTERING,
	/** The current message is talking about the Translate module. */
	MODE_TRANSLATE,
};

enum config_operation {
	/* The following make sense when the mode is pool6, pool4, BIB or session. */

	/** The userspace app wants to print the table being requested. */
	OP_DISPLAY,
	/** The userspace app wants to print the number of records in the table being requested. */
	OP_COUNT,
	/** The userspace app wants to add an element to the table being requested. */
	OP_ADD,
	/** The userspace app wants to delete an element from the table being requested. */
	OP_REMOVE,

	/* The following make sense when mode is filtering or translate. */

	/**
	 * @{
	 * When this bit is on, the userspace app wants to update the corresponding value.
	 */
	#define RESET_TCLASS_MASK		(1 << 2)
	#define RESET_TOS_MASK			(1 << 3)
	#define NEW_TOS_MASK			(1 << 4)
	#define DF_ALWAYS_ON_MASK		(1 << 5)
	#define BUILD_IPV4_ID_MASK		(1 << 6)
	#define LOWER_MTU_FAIL_MASK		(1 << 7)
	#define MTU_PLATEAUS_MASK		(1 << 8)
	#define MIN_IPV6_MTU_MASK		(1 << 9)

	#define DROP_BY_ADDR_MASK		(1 << 0)
	#define DROP_ICMP6_INFO_MASK	(1 << 1)
	#define DROP_EXTERNAL_TCP_MASK	(1 << 2)
	#define UDP_TIMEOUT_MASK		(1 << 3)
	#define ICMP_TIMEOUT_MASK		(1 << 4)
	#define TCP_EST_TIMEOUT_MASK	(1 << 5)
	#define TCP_TRANS_TIMEOUT_MASK 	(1 << 6)
	/**
	 * @}
	 */
};

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 */
struct request_hdr {
	/** Size of the message. Includes header (this one) and payload. */
	__u32 length;
	/** See "enum config_mode". */
	__u16 mode;
	/** See "enum config_operation". */
	__u32 operation;
};

/**
 * A BIB entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct bib_entry" and only used when BIB entries need to travel to
 * userspace. For anything else, use "struct bib_entry".
 *
 * See "struct bib_entry" for documentation on the fields.
 */
struct bib_entry_usr {
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
	bool is_static;
};

/**
 * A session entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct session_entry" and only used when sessions need to travel to
 * userspace. For anything else, use "struct session_entry".
 *
 * See "struct session_entry" for documentation on the fields.
 */
struct session_entry_usr {
	struct ipv6_pair ipv6;
	struct ipv4_pair ipv4;
	__u64 dying_time;
	l4_protocol l4_proto;
};

/**
 * Configuration of the "Session DB" module. See "struct full_filtering_config".
 */
struct sessiondb_config {
	struct timeouts {
		/** Maximum number of seconds inactive UDP sessions will remain in the DB. */
		__u64 udp;
		/** Maximum number of seconds inactive ICMP sessions will remain in the DB. */
		__u64 icmp;
		/** Max number of seconds established and inactive TCP sessions will remain in the DB. */
		__u64 tcp_est;
		/** Max number of seconds transitory and inactive TCP sessions will remain in the DB. */
		__u64 tcp_trans;
	} ttl;
};

/**
 * Configuration for the "Filtering and Updating" module.
 */
struct filtering_config {
	/** Use Address-Dependent Filtering? */
	bool drop_by_addr;
	/** Filter ICMPv6 Informational packets? */
	bool drop_icmp6_info;
	/** Drop externally initiated TCP connections? (IPv4 initiated) */
	bool drop_external_tcp;
};

/**
 * This exists because of historical reasons. The timeouts used to be part of Filtering; we moved
 * that to the session database, but we kept the interface of the userspace application.
 * (so the user configures the session DB via filtering).
 */
struct full_filtering_config {
	struct filtering_config filtering;
	struct sessiondb_config sessiondb;
};

/**
 * Configuration for the "Translate the packet" module.
 */
struct translate_config {
	/**
	 * "true" if the Traffic Class field of the translated IPv6 header should always be set to zero.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 */
	bool reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of the translated IPv4 header should always be set
	 * to "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class field.
	 */
	bool reset_tos;
	/**
	 * If "reset_tos" is "true", this is the value the translator will always write in the TOS field
	 * of the translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;
	/**
	 * If "true", the translator will always set the translated IPv4 header's Don't Fragment (DF)
	 * flag to one.
	 * Otherwise the flag will be set depending on the packet's length.
	 */
	bool df_always_on;
	/**
	 * Whether the translated IPv4 header's Identification field should be computed (Either from the
	 * IPv6 fragment header's Identification field or deduced from the packet's length).
	 * Otherwise it will always be set to zero.
	 */
	bool build_ipv4_id;
	/**
	 * "true" if the value for the MTU field of outgoing ICMPv6 fragmentation needed packets should
	 * be set to no less than 1280, regardless of MTU plateaus and whatnot.
	 * See RFC 6145 section 6, second approach.
	 */
	bool lower_mtu_fail;
	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;
	/**
	 * If the translator detects the source of the incoming packet does not implement RFC 1191,
	 * these are the plateau values used to determine a likely path MTU for outgoing ICMPv6
	 * fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is less than the incoming
	 * packet's Total Length field.
	 * Default value is { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }.
	 */
	__u16 *mtu_plateaus;

	/**
	 * The smallest MTU in the IPv6 side. Jool will ensure that packets traveling from 4 to 6 will
	 * be no bigger than this amount of bytes.
	 */
	__u16 min_ipv6_mtu;
};

/**
 * Configuration for the "IPv6 Pool" module.
 */
union request_pool6 {
	struct {
		/* Nothing needed here ATM. */
	} display;
	struct {
		/** The prefix the user wants to add or remove from the pool. */
		struct ipv6_prefix prefix;
	} update;
};

/**
 * Configuration for the "IPv4 Pool" module.
 */
union request_pool4 {
	struct {
		/* Nothing needed there ATM. */
	} display;
	struct {
		/** The address the user wants to add or remove from the pool. */
		struct in_addr addr;
	} update;
};

/**
 * Configuration for the "BIB" module.
 */
struct request_bib {
	/** Table the userspace app wants to display or edit. */
	l4_protocol l4_proto;
	union {
		struct {
			/** If this is false, this is the first chunk the app is requesting. */
			bool iterate;
			/**
			 * Address the userspace app received in the last chunk. Iteration should contiue
			 * from here.
			 */
			struct ipv4_tuple_address ipv4;
		} display;
		struct {
			/* Nothing needed here. */
		} count;
		struct {
			/** The IPv6 transport address of the entry the user wants to add. */
			struct ipv6_tuple_address ipv6;
			/** The IPv4 transport address of the entry the user wants to add. */
			struct ipv4_tuple_address ipv4;
		} add;
		struct {
			/** Indicator of which element (from the union below) is the valid one. */
			l3_protocol l3_proto;
			union {
				/** The IPv6 transport address of the entry the user wants to remove. */
				struct ipv6_tuple_address ipv6;
				/** The IPv4 transport address of the entry the user wants to remove. */
				struct ipv4_tuple_address ipv4;
			};
		} remove;
		struct {
			/* Nothing needed here. */
		} clear;
	};
};

/**
 * Configuration for the "Session DB"'s tables.
 * Only the "OP_DISPLAY" and "OP_COUNT" operations make sense in this module.
 */
struct request_session {
	/** Table the userspace app wants to display. */
	l4_protocol l4_proto;
	union {
		struct {
			/** If this is false, this is the first chunk the app is requesting. */
			bool iterate;
			/**
			 * Address the userspace app received in the last chunk. Iteration should contiue
			 * from here.
			 */
			struct ipv4_tuple_address ipv4;
		} display;
		struct {
			/* Nothing needed here. */
		} count;
	};
};

/*
 * Because of the somewhat intrusive nature of the netlink header, response header structures are
 * not really necessary.
 */

/**
 * "struct translate_config" has pointers, so if the userspace app wants Translate's configuration,
 * the structure cannot simply be copied to userspace.
 * This translates "config" and its subobjects into a byte array which can then be transformed back
 * using "deserialize_translate_config()".
 */
int serialize_translate_config(struct translate_config *config,
		unsigned char **buffer_out, __u16 *buffer_len_out);
/**
 * Reverts the work of serialize_translate_config() by creating "config" out of the byte array
 * "buffer".
 */
int deserialize_translate_config(void *buffer, __u16 buffer_len,
		struct translate_config *target_out);


#endif /* _JOOL_COMM_CONFIG_PROTO_H */
