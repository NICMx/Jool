#ifndef _JOOL_COMMON_CONFIG_H
#define _JOOL_COMMON_CONFIG_H

/**
 * @file
 * Elements visible to both the kernel module and the userspace application, and which they use to
 * communicate with each other.
 *
 * If you see a "__u8", keep in mind it might be intended as a boolean. sizeof(bool) is
 * implementation defined, which is unacceptable because these structures define a communication
 * protocol.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include "nat64/common/types.h"
#include "nat64/common/xlat.h"
/* TODO really necessary? */
#ifdef BENCHMARK
	#ifdef __KERNEL__
		#include <linux/time.h>
	#else
		#include <time.h>
	#endif
#endif

/**
 * ID of Netlink messages Jool listens to.
 * This value was chosen at random, if I remember correctly.
 * TODO you sure this is sane? 0x22 > 32.
 */
#define MSG_TYPE_JOOL (0x20 + 2)
#define MSG_TYPE_JOOL_DONE (0x20+4)
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
	/** The current message is talking about global configuration values. */
	MODE_GLOBAL = (1 << 0),
	/** The current message is talking about the IPv6 pool. */
	MODE_POOL6 = (1 << 1),
	/** The current message is talking about the IPv4 pool. */
	MODE_POOL4 = (1 << 2),
	/** The current message is talking about the blacklisted addresses pool. */
	MODE_BLACKLIST = (1 << 8),
	/** The current message is talking about the RFC6791 pool. */
	MODE_RFC6791 = (1 << 7),
	/** The current message is talking about the EAMT. */
	MODE_EAMT = (1 << 6),
	/** The current message is talking about the Binding Information Bases. */
	MODE_BIB = (1 << 3),
	/** The current message is talking about the session tables. */
	MODE_SESSION = (1 << 4),
	/** The current message is talking about log times for benchmark. */
	MODE_LOGTIME = (1 << 5),
	/** The current message is talking about the JSON configuration file */
	MODE_PARSE_FILE = (1 << 9),
	/** The current message is talking about synchronization entries.*/
	MODE_JOOLD = (1 << 10),
};

/**
 * @{
 * Allowed operations for the mode mentioned in the name.
 * eg. BIB_OPS = Allowed operations for BIB requests.
 */
#define DATABASE_OPS (OP_DISPLAY | OP_COUNT | OP_ADD | OP_REMOVE | OP_FLUSH)

#define GLOBAL_OPS (OP_DISPLAY | OP_UPDATE)
#define POOL6_OPS (DATABASE_OPS)
#define POOL4_OPS (DATABASE_OPS)
#define BLACKLIST_OPS (DATABASE_OPS)
#define RFC6791_OPS (DATABASE_OPS)
#define EAMT_OPS (DATABASE_OPS)
#define BIB_OPS (DATABASE_OPS & ~OP_FLUSH)
#define SESSION_OPS (OP_DISPLAY | OP_COUNT)
#define LOGTIME_OPS (OP_DISPLAY)
/**
 * @}
 */

enum config_operation {
	/** The userspace app wants to print the stuff being requested. */
	OP_DISPLAY = (1 << 0),
	/** The userspace app wants to print the number of records in the table being requested. */
	OP_COUNT = (1 << 1),
	/** The userspace app wants to add an element to the table being requested. */
	OP_ADD = (1 << 2),
	/* The userspace app wants to edit some value. */
	OP_UPDATE = (1 << 3),
	/** The userspace app wants to delete an element from the table being requested. */
	OP_REMOVE = (1 << 4),
	/* The userspace app wants to clear some table. */
	OP_FLUSH = (1 << 5),
};

struct global_bits {
	__u8 manually_enabled;
	__u8 address_dependent_filtering;
	__u8 drop_icmpv6_info;
	__u8 drop_externally_initiated_tcp;
	__u8 udp_timeout;
	__u8 tcp_est_timeout;
	__u8 tcp_trans_timeout;
	__u8 icmp_timeout;
	__u8 fragment_arrival_timeout;
	__u8 maximum_simultaneous_opens;
	__u8 source_icmpv6_errors_better;
	__u8 logging_bib;
	__u8 logging_session;
	__u8 zeroize_traffic_class;
	__u8 override_tos;
	__u8 tos;
	__u8 mtu_plateaus;
	__u8 amend_udp_checksum_zero;
	__u8 randomize_rfc6791_addresses;
};

enum parse_section {
	SEC_GLOBAL = 1,
	SEC_POOL6 = 2,
	SEC_POOL4 = 4,
	SEC_BIB = 8,
	SEC_COMMIT = 16,
	SEC_EAMT = 32,
	SEC_BLACKLIST = 64,
	SEC_POOL6791 = 128,
	SEC_INIT = 256
};

/* TODO NO-NO. */
enum parse_entries_size {
	POOL4_ENTRY_SIZE = 16,
	BIB_ENTRY_SIZE = 25,
	EAMT_ENTRY_SIZE = 22,
	BLACKLIST_ENTRY_SIZE = 5,
	POOL6791_ENTRY_SIZE = 5
};

/**
 * @{
 * Allowed modes for the operation mentioned in the name.
 * eg. DISPLAY_MODES = Allowed modes for display operations.
 */
#define POOL_MODES (MODE_POOL6 | MODE_POOL4 | MODE_BLACKLIST | MODE_RFC6791)
#define TABLE_MODES (MODE_EAMT | MODE_BIB | MODE_SESSION)

#define DISPLAY_MODES (MODE_GLOBAL | POOL_MODES | TABLE_MODES | MODE_LOGTIME)
#define COUNT_MODES (POOL_MODES | TABLE_MODES)
#define ADD_MODES (POOL_MODES | MODE_EAMT | MODE_BIB)
#define REMOVE_MODES (POOL_MODES | MODE_EAMT | MODE_BIB)
#define FLUSH_MODES (POOL_MODES | MODE_EAMT)
#define UPDATE_MODES (MODE_GLOBAL | MODE_PARSE_FILE)

#define SIIT_MODES (MODE_GLOBAL | MODE_POOL6 | MODE_BLACKLIST | MODE_RFC6791 \
		| MODE_EAMT | MODE_LOGTIME | MODE_PARSE_FILE)
#define NAT64_MODES (MODE_GLOBAL | MODE_POOL6 | MODE_POOL4 | MODE_BIB \
		| MODE_SESSION | MODE_LOGTIME | MODE_PARSE_FILE)
/**
 * @}
 */

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 */
struct request_hdr {
	/** Protocol magic header (always "jool"). */
	char magic[4];
	/** Translation type (SIIT or NAT64) */
	char type;
	/** Jool's version. */
	__u32 version;
	/** Size of the message. Includes header (this one) and payload. */
	__u32 length;
	/** See "enum config_mode". */
	__u16 mode;
	/** See "enum config_operation". */
	__u8 operation;
};

static inline void init_request_hdr(struct request_hdr *hdr, __u32 length,
		enum config_mode mode, enum config_operation operation)
{
	hdr->magic[0] = 'j';
	hdr->magic[1] = 'o';
	hdr->magic[2] = 'o';
	hdr->magic[3] = 'l';
	hdr->type = xlat_is_nat64() ? 'n' : 's'; /* 'n'at64 or 's'iit. */
	hdr->version = xlat_version();
	hdr->length = length;
	hdr->mode = mode;
	hdr->operation = operation;
}

/**
 * Configuration for the "IPv6 Pool" module.
 */
union request_pool6 {
	struct {
		__u8 prefix_set;
		struct ipv6_prefix prefix;
	} display;
	struct {
		/** The prefix the user wants to add to the pool. */
		struct ipv6_prefix prefix;
	} add;
	struct {
		/** The prefix the user wants to update to the pool. */
		struct ipv6_prefix prefix;
	} update;
	struct {
		/** The prefix the user wants to remove from the pool. */
		struct ipv6_prefix prefix;
		/* Whether the prefix's sessions should be cleared too (false) or not (true). */
		__u8 quick;
	} rm;
	struct {
		/* Whether the sessions tables should also be cleared (false) or not (true). */
		__u8 quick;
	} flush;
};

/**
 * Configuration for the "IPv4 Pool" module.
 */
union request_pool4 {
	struct {
		__u8 offset_set;
		struct pool4_sample offset;
	} display;
	struct {
		__u32 mark;
		__u8 proto;
		/** The addresses the user wants to add to the pool. */
		struct ipv4_prefix addrs;
		struct port_range ports;
	} add;
	struct {
		__u32 mark;
		__u8 proto;
		/** The addresses the user wants to remove from the pool. */
		struct ipv4_prefix addrs;
		struct port_range ports;
		/* Whether the address's BIB entries and sessions should be cleared too (false) or not (true). */
		__u8 quick;
	} rm;
	struct {
		/* Whether the BIB and the sessions tables should also be cleared (false) or not (true). */
		__u8 quick;
	} flush;
};

union request_pool {
	struct {
		__u8 offset_set;
		struct ipv4_prefix offset;
	} display;
	struct {
		/** The addresses the user wants to add to the pool. */
		struct ipv4_prefix addrs;
	} add;
	struct {
		/** The addresses the user wants to remove from the pool. */
		struct ipv4_prefix addrs;
	} rm;
	struct {
		/* Nothing needed here. */
	} flush;
};

/**
 * Configuration for the "EAM" module.
 */
union request_eamt {
	struct {
		__u8 prefix4_set;
		struct ipv4_prefix prefix4;
	} display;
	struct {
		/* Nothing needed here. */
	} count;
	struct {
		struct ipv6_prefix prefix6;
		struct ipv4_prefix prefix4;
		/* TODO this might have been moved over to the userspace app. */
		__u8 force;
	} add;
	struct {
		__u8 prefix6_set;
		struct ipv6_prefix prefix6;
		__u8 prefix4_set;
		struct ipv4_prefix prefix4;
	} rm;
	struct {
		/* Nothing needed here ATM. */
	} flush;
};

/**
 * Configuration for the "Log time" module.
 */
struct request_logtime {
	__u8 l3_proto;
	__u8 l4_proto;
	union {
		struct {
			/** If this is false, this is the first chunk the app is requesting. (boolean) */
			__u8 iterate;
		} display;
	};
};

/**
 * Configuration for the "BIB" module.
 */
struct request_bib {
	/** Table the userspace app wants to display or edit. See enum l4_protocol. */
	__u8 l4_proto;
	union {
		struct {
			__u8 addr4_set;
			/**
			 * Address the userspace app received in the last chunk. Iteration should contiue
			 * from here.
			 */
			struct ipv4_transport_addr addr4;
		} display;
		struct {
			/* Nothing needed here. */
		} count;
		struct {
			/** The IPv6 transport address of the entry the user wants to add. */
			struct ipv6_transport_addr addr6;
			/** The IPv4 transport address of the entry the user wants to add. */
			struct ipv4_transport_addr addr4;
		} add;
		struct {
			/* Is the value if "addr6" set? (boolean) */
			__u8 addr6_set;
			/** The IPv6 transport address of the entry the user wants to remove. */
			struct ipv6_transport_addr addr6;
			/* Is the value if "addr4" set? (boolean) */
			__u8 addr4_set;
			/** The IPv4 transport address of the entry the user wants to remove. */
			struct ipv4_transport_addr addr4;
		} rm;
	};
};

/**
 * Configuration for the "Session DB"'s tables.
 */
struct request_session {
	/** Table the userspace app wants to display. See enum l4_protocol. */
	__u8 l4_proto;
	union {
		struct {
			/** Are remote4 and local4 set? */
			__u8 connection_set;
			/**
			 * Remote node from the connection the userspace app
			 * received in the last chunk. Iteration should continue
			 * from here.
			 */
			struct ipv4_transport_addr remote4;
			/**
			 * Remote IPv6 node's IPv4 mask, from the connection the
			 * userspace app received in the last chunk.
			 * Iteration should continue from here.
			 */
			struct ipv4_transport_addr local4;
		} display;
		struct {
			/* Nothing needed here. */
		} count;
	};
};

/**
 * Indicators of the respective fields in the sessiondb_config structure.
 */
enum global_type {
	/* NAT64 */
	UDP_TIMEOUT,
	ICMP_TIMEOUT,
	TCP_EST_TIMEOUT,
	TCP_TRANS_TIMEOUT,
	FRAGMENT_TIMEOUT,

	MAX_PKTS,
	SRC_ICMP6ERRS_BETTER,

	BIB_LOGGING,
	SESSION_LOGGING,

	DROP_BY_ADDR,
	DROP_ICMP6_INFO,
	DROP_EXTERNAL_TCP,

	SYNCH_ENABLE,
	SYNCH_DISABLE,
	SYNCH_ELEMENTS_LIMIT,
	SYNCH_PERIOD,
	SYNCH_THRESHOLD,

	/* SIIT */
	COMPUTE_UDP_CSUM_ZERO,
	EAM_HAIRPINNING_MODE,
	RANDOMIZE_RFC6791,

	/* Common */
	RESET_TCLASS,
	RESET_TOS,
	NEW_TOS,
	DF_ALWAYS_ON,
	BUILD_IPV6_FH,
	BUILD_IPV4_ID,
	LOWER_MTU_FAIL,
	MTU_PLATEAUS,
	DISABLE,
	ENABLE,
	ATOMIC_FRAGMENTS,
};

/**
 * A request to edit a miscellaneous configuration value.
 */
union request_global {
	struct {
		/* Nothing needed here. */
	} display;
	struct {
		__u8 type;
		/* The value is given in a variable-sized payload so it's not here. */
	} update;
};

struct response_pool4_count {
	__u32 tables;
	__u64 samples;
	__u64 taddrs;
};

#ifdef BENCHMARK

/**
 * A logtime node entry, from the eyes of userspace.
 *
 * It holds the "struct timespec" which include seconds and nanoseconds, that specific how time
 * the skb need to be translated to IPv6 -> IPv4 or IPv4 -> IPv6.
 */
struct logtime_entry_usr {
	struct timespec time;
};

#endif

/**
 * A BIB entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct bib_entry" and only used when BIB entries need to travel to
 * userspace. For anything else, use "struct bib_entry".
 *
 * See "struct bib_entry" for documentation on the fields.
 */
struct bib_entry_usr {
	struct ipv4_transport_addr addr4;
	struct ipv6_transport_addr addr6;
	__u8 is_static;
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
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	__u64 dying_time;
	__u8 state;
};

/**
 * Explicit Address Mapping definition.
 * Intended to be a row in the Explicit Address Mapping Table, bind an IPv4
 * Prefix to an IPv6 Prefix and vice versa.
 */
struct eamt_entry {
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
};

/**
 * A copy of the entire running configuration, excluding databases.
 */
struct global_config {
	/**
	 * Is Jool actually translating?
	 * This depends on several factors depending on stateness, and is not an actual variable Jool
	 * stores; it is computed as it is requested.
	 * Boolean.
	 */
	__u8 jool_status;
	/**
	 * Did the user manually instruct Jool to sit idle?
	 * Boolean.
	 */
	__u8 is_disable;

	/**
	 * "true" if the Traffic Class field of translated IPv6 headers should always be zeroized.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 * Boolean.
	 */
	__u8 reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of translated IPv4 headers should always be set
	 * as "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class field.
	 * Boolean.
	 */
	__u8 reset_tos;
	/**
	 * If "reset_tos" is "true", this is the value the translator will always write in the TOS
	 * field of translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;

	struct {
		/**
		 * If "true", the translator will always set translated IPv4 headers' Don't Fragment (DF)
		 * flags as one.
		 * Otherwise the value of the flag will depend on the packet's length.
		 * Boolean.
		 */
		__u8 df_always_on;
		/**
		 * If the incoming IPv4 packet is a fragment, Jool will include a fragment header in the
		 * translated IPv6 packet.
		 * If this is "true", Jool will also include a Fragment Header if DF is false.
		 * Boolean.
		 */
		__u8 build_ipv6_fh;
		/**
		 * Whether translated IPv4 headers' Identification fields should be computed (Either from the
		 * IPv6 fragment header's Identification field or deduced from the packet's length).
		 * Otherwise it will always be set as zero.
		 * Boolean.
		 */
		__u8 build_ipv4_id;
		/**
		 * "true" if the value for MTU fields of outgoing ICMPv6 fragmentation needed packets should
		 * be set as no less than 1280, regardless of MTU plateaus and whatnot.
		 * See RFC 6145 section 6, second approach.
		 * Boolean.
		 */
		__u8 lower_mtu_fail;
	} atomic_frags;

	/**
	 * If the translator detects the source of the incoming packet does not implement RFC 1191,
	 * these are the plateau values used to determine a likely path MTU for outgoing ICMPv6
	 * fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is less than the incoming
	 * packet's Total Length field.
	 */
	__u16 *mtu_plateaus;
	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;

	struct {
		/**
		 * Time values in this structure should be read as jiffies in the kernel, milliseconds in
		 * userspace.
		 * The kernel module is responsible for switching units as the the values approach the border.
		 */
		struct {
			/** Maximum time fragments will remain in the DB. */
			__u64 frag;
		} ttl;

		/** Use Address-Dependent Filtering? (boolean) */
		__u8 drop_by_addr;
		/** Filter ICMPv6 Informational packets? (boolean) */
		__u8 drop_icmp6_info;
		/** Drop externally initiated TCP connections? (IPv4 initiated) (boolean) */
		__u8 drop_external_tcp;

		/** True = issue #132 behaviour. False = RFC 6146 behaviour. (boolean) */
		__u8 src_icmp6errs_better;
	} nat64;

	struct {
		/**
		 * Amend the UDP checksum of incoming IPv4-UDP packets when it's zero?
		 * Otherwise these packets will be dropped (because they're illegal in IPv6).
		 * Boolean.
		 */
		__u8 compute_udp_csum_zero;
		/**
		 * Randomize choice of RFC6791 address?
		 * Otherwise it will be set depending on the incoming packet's Hop Limit. See
		 * https://github.com/NICMx/NAT64/issues/130.
		 * Boolean.
		 */
		__u8 randomize_error_addresses;
		/**
		 * How should hairpinning be handled by EAM-translated packets.
		 * See @eam_hairpinning_mode.
		 */
		__u8 eam_hairpin_mode;
	} siit;

	/** Tells if synchronization is enabled*/
	__u8 synch_enabled;

	/**
	 * Max number of elemets to store in the synchronization queue before
	 * send them to another jool's instance.
	 */
	__u32 synch_elements_limit;

	/**
	 * Time lapse within the timer will be sending sessions to
	 * another jool's instance if there are any in the synchronization
	 * queue.
	 */
	__u32 synch_elements_period;

	/**
	 * Milliseconds that have to pass since a session was created for it to be allowed to
	 * get into the synchronization queue, this is intended to reduce synchronization traffic
	 * over the network.
	 */

	__u32 synch_elements_threshold;

};

/**
 * The modes are defined by the latest version of the EAM draft.
 *
 * They are exclusive, so this needn't be considered bit fields.
 */
enum eam_hairpinning_mode {
	EAM_HAIRPIN_OFF = 0,
	EAM_HAIRPIN_SIMPLE = 1,
	EAM_HAIRPIN_INTRINSIC = 2,

#define EAM_HAIRPIN_MODE_COUNT 3
};

/**
 * "struct global_config" has pointers, so if the userspace app wants the configuration,
 * the structure cannot simply be copied to userspace.
 * This translates "config" and its subobjects into a byte array which can then be transformed back
 * using "deserialize_global_config()".
 */
int serialize_global_config(struct global_config *config, bool pools_empty,
		unsigned char **buffer_out, size_t *buffer_len_out);
/**
 * Reverts the work of serialize_translate_config() by creating "config" out of the byte array
 * "buffer".
 */
int deserialize_global_config(void *buffer, __u16 buffer_len, struct global_config *config);


#endif /* _JOOL_COMMON_CONFIG_H */
