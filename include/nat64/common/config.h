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
 */

#include "nat64/common/types.h"
#include "nat64/common/xlat.h"
/* TODO (usr) really necessary? */
#ifdef BENCHMARK
	#ifdef __KERNEL__
		#include <linux/time.h>
	#else
		#include <time.h>
	#endif
#endif

#define GNL_JOOL_FAMILY_NAME (xlat_is_siit() ? "SIIT_Jool" : "NAT64_Jool")
#define GNL_JOOLD_MULTICAST_GRP_NAME "joold"

enum genl_mc_group_ids {
	JOOLD_MC_ID = (1 << 0),
};

enum genl_commands {
	JOOL_COMMAND,
};

enum attributes {
	ATTR_DUMMY,
	ATTR_DATA,
	__ATTR_MAX,
};

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

	MODE_INSTANCE = (1 << 11),
};

/**
 * @{
 * Allowed operations for the mode mentioned in the name.
 * eg. BIB_OPS = Allowed operations for BIB requests.
 */
#define DATABASE_OPS (OP_DISPLAY | OP_COUNT | OP_ADD | OP_REMOVE | OP_FLUSH)
#define ANY_OP 0xFFFF

#define GLOBAL_OPS (OP_DISPLAY | OP_UPDATE)
#define POOL6_OPS (DATABASE_OPS)
#define POOL4_OPS (DATABASE_OPS)
#define BLACKLIST_OPS (DATABASE_OPS)
#define RFC6791_OPS (DATABASE_OPS)
#define EAMT_OPS (DATABASE_OPS)
#define BIB_OPS (DATABASE_OPS & ~OP_FLUSH)
#define SESSION_OPS (OP_DISPLAY | OP_COUNT)
#define JOOLD_OPS (OP_ADVERTISE | OP_TEST)
#define LOGTIME_OPS (OP_DISPLAY)
#define INSTANCE_OPS (OP_ADD | OP_REMOVE)
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
	/** The userspace app wants to edit some value. */
	OP_UPDATE = (1 << 3),
	/** The userspace app wants to delete an element from the table being requested. */
	OP_REMOVE = (1 << 4),
	/** The userspace app wants to clear some table. */
	OP_FLUSH = (1 << 5),
	/** The userspace app wants us to shout something somewhere. */
	OP_ADVERTISE = (1 << 6),
	/** The userspace app wants to test something. */
	OP_TEST = (1 << 7),
	/** Somebody is acknowledging a previous message. */
	OP_ACK = (1 << 8),
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

/**
 * @{
 * Allowed modes for the operation mentioned in the name.
 * eg. DISPLAY_MODES = Allowed modes for display operations.
 */
#define POOL_MODES (MODE_POOL6 | MODE_POOL4 | MODE_BLACKLIST | MODE_RFC6791)
#define TABLE_MODES (MODE_EAMT | MODE_BIB | MODE_SESSION)
#define ANY_MODE 0xFFFF

#define DISPLAY_MODES (MODE_GLOBAL | POOL_MODES | TABLE_MODES | MODE_LOGTIME)
#define COUNT_MODES (POOL_MODES | TABLE_MODES)
#define ADD_MODES (POOL_MODES | MODE_EAMT | MODE_BIB | MODE_INSTANCE)
#define REMOVE_MODES (POOL_MODES | MODE_EAMT | MODE_BIB | MODE_INSTANCE)
#define FLUSH_MODES (POOL_MODES | MODE_EAMT)
#define UPDATE_MODES (MODE_GLOBAL | MODE_PARSE_FILE)

#define SIIT_MODES (MODE_GLOBAL | MODE_POOL6 | MODE_BLACKLIST | MODE_RFC6791 \
		| MODE_EAMT | MODE_LOGTIME | MODE_PARSE_FILE | MODE_INSTANCE)
#define NAT64_MODES (MODE_GLOBAL | MODE_POOL6 | MODE_POOL4 | MODE_BIB \
		| MODE_SESSION | MODE_LOGTIME | MODE_PARSE_FILE \
		| MODE_INSTANCE | MODE_JOOLD)
/**
 * @}
 */

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 */
struct request_hdr {
	/** Protocol magic header (always "jool"). */
	__u8 magic[4];
	/** Translation type (SIIT or NAT64) */
	__u8 type;
	/**
	 * 'u'nicast or 'm'ulticast. Only userspace joold needs it, so most of
	 * the time this field is ignored.
	 *
	 * This exists because I haven't found a way for joold to tell whether a
	 * kernel packet is a multicast request or a unicast response.
	 * TODO (fine) Find a way to do that?
	 */
	__u8 castness;

	/**
	 * http://www.catb.org/esr/structure-packing/
	 * Explicit unused space for future functionality and to ensure
	 * sizeof(struct request_hdr) is a power of 2.
	 */
	__be16 slop;

	/** Jool's version. */
	__be32 version;
	/** See "enum config_mode". */
	__be16 mode;
	/** See "enum config_operation". */
	__be16 operation;
};

void init_request_hdr(struct request_hdr *hdr, enum config_mode mode,
		enum config_operation operation);
int validate_request(void *data, size_t data_len, char *sender, char *receiver);

struct response_hdr {
	struct request_hdr req;
	__u16 error_code;
	__u8 pending_data;
};

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

struct pool4_entry_usr {
	__u32 mark;
	__u8 proto;
	struct ipv4_range range;
};

/**
 * Configuration for the "IPv4 Pool" module.
 */
union request_pool4 {
	struct {
		__u8 proto;
		__u8 offset_set;
		struct pool4_sample offset;
	} display;
	struct {
		struct pool4_entry_usr entry;
	} add;
	struct {
		struct pool4_entry_usr entry;
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
		/** Add @addrs even if it contains subnet-scoped addresses? */
		bool force;
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
		/* TODO (usr) this might have been moved over to the userspace app. */
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
			/** Is offset set? */
			__u8 offset_set;
			/**
			 * Connection the userspace app received in the last
			 * chunk. Iteration should continue from here.
			 */
			struct taddr6_tuple offset;
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
	/* Common */
	ENABLE = 1024,
	DISABLE,
	ENABLE_BOOL,
	RESET_TCLASS,
	RESET_TOS,
	NEW_TOS,
	ATOMIC_FRAGMENTS,
	DF_ALWAYS_ON,
	BUILD_IPV6_FH,
	BUILD_IPV4_ID,
	LOWER_MTU_FAIL,
	MTU_PLATEAUS,

	/* SIIT */
	COMPUTE_UDP_CSUM_ZERO,
	RANDOMIZE_RFC6791,
	EAM_HAIRPINNING_MODE,

	/* NAT64 */
	DROP_BY_ADDR,
	DROP_ICMP6_INFO,
	DROP_EXTERNAL_TCP,
	SRC_ICMP6ERRS_BETTER,
	F_ARGS,
	UDP_TIMEOUT,
	ICMP_TIMEOUT,
	TCP_EST_TIMEOUT,
	TCP_TRANS_TIMEOUT,
	FRAGMENT_TIMEOUT,
	BIB_LOGGING,
	SESSION_LOGGING,
	MAX_PKTS,
	SYNCH_ENABLE,
	SYNCH_DISABLE,
	SYNCH_FLUSH_ASAP,
	SYNCH_FLUSH_DEADLINE,
	SYNCH_CAPACITY,
	SYNCH_MAX_PAYLOAD,
	RFC6791V6_PREFIX
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
	__u8 l4_proto;
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
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;
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

enum f_args {
	F_ARGS_SRC_ADDR = (1 << 3),
	F_ARGS_SRC_PORT = (1 << 2),
	F_ARGS_DST_ADDR = (1 << 1),
	F_ARGS_DST_PORT = (1 << 0),
};

#define PLATEAUS_MAX 64

/**
 * A copy of the entire running configuration, excluding databases.
 */
struct global_config {
	/**
	 * Is Jool actually translating?
	 * This depends on several factors depending on stateness, and is not an
	 * actual variable Jool stores; it is computed as it is requested.
	 * Boolean.
	 */
	__u8 status;
	/**
	 * Does the user wants this Jool instance to translate packets?
	 * Boolean.
	 */
	__u8 enabled;

	/**
	 * "true" if the Traffic Class field of translated IPv6 headers should
	 * always be zeroized.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 * Boolean.
	 */
	__u8 reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of translated IPv4 headers
	 * should always be set as "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class
	 * field.
	 * Boolean.
	 */
	__u8 reset_tos;
	/**
	 * If "reset_tos" is "true", this is the value the translator will
	 * always write in the TOS field of translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;

	struct {
		/**
		 * If "true", the translator will always set translated IPv4
		 * headers' Don't Fragment (DF) flags as one.
		 * Otherwise the value of the flag will depend on the packet's
		 * length.
		 * Boolean.
		 */
		__u8 df_always_on;
		/**
		 * If the incoming IPv4 packet is a fragment, Jool will include
		 * a fragment header in the translated IPv6 packet.
		 * If this is "true", Jool will also include a Fragment Header
		 * if DF is false.
		 * Boolean.
		 */
		__u8 build_ipv6_fh;
		/**
		 * Whether translated IPv4 headers' Identification fields should
		 * be computed (Either from the IPv6 fragment header's
		 * Identification field or deduced from the packet's length).
		 * Otherwise it will always be set as zero.
		 * Boolean.
		 */
		__u8 build_ipv4_id;
		/**
		 * "true" if the value for MTU fields of outgoing ICMPv6
		 * fragmentation needed packets should be set as no less than
		 * 1280, regardless of MTU plateaus and whatnot.
		 * See RFC 6145 section 6, second approach.
		 * Boolean.
		 */
		__u8 lower_mtu_fail;
	} atomic_frags;

	/**
	 * If the translator detects the source of the incoming packet does not
	 * implement RFC 1191, these are the plateau values used to determine a
	 * likely path MTU for outgoing ICMPv6 fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is
	 * less than the incoming packet's Total Length field.
	 */
	__u16 mtu_plateaus[PLATEAUS_MAX];
	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;

	union {
		struct {
			/**
			 * Amend the UDP checksum of incoming IPv4-UDP packets
			 * when it's zero? Otherwise these packets will be
			 * dropped (because they're illegal in IPv6).
			 * Boolean.
			 */
			__u8 compute_udp_csum_zero;
			/**
			 * Randomize choice of RFC6791 address?
			 * Otherwise it will be set depending on the incoming
			 * packet's Hop Limit.
			 * See https://github.com/NICMx/Jool/issues/130.
			 * Boolean.
			 */
			__u8 randomize_error_addresses;
			/**
			 * How should hairpinning be handled by EAM-translated
			 * packets.
			 * See @eam_hairpinning_mode.
			 */
			__u8 eam_hairpin_mode;

			/**
			 * States if the rfc6791_v6_prefix configuration
			 * attribute has been set. If this flag is true then
			 * the value of rfc6791_v6_prefix is going to be used
			 */
			__u8 use_rfc6791_v6;
			/**
			 * Address used to represent a not translatable source
			 * address of an incoming packet.
			 */
			struct ipv6_prefix rfc6791_v6_prefix;

		} siit;
		struct {
			/** Use Address-Dependent Filtering? (boolean) */
			__u8 drop_by_addr;
			/** Filter ICMPv6 Informational packets? (boolean) */
			__u8 drop_icmp6_info;
			/**
			 * Drop externally initiated (IPv4) TCP connections?
			 * (boolean)
			 */
			__u8 drop_external_tcp;

			/**
			 * True = issue #132 behaviour.
			 * False = RFC 6146 behaviour.
			 * (boolean)
			 */
			__u8 src_icmp6errs_better;
			/**
			 * Fields of the packet that will be sent to the F() function.
			 * (RFC 6056 algorithm 3.)
			 * See "enum f_args".
			 */
			__u8 f_args;
		} nat64;
	};
};

struct bib_config {
	__u8 log_changes;
};

/* This has to be <= 32. */
#define JOOLD_MULTICAST_GROUP 30
#define JOOLD_MAX_PAYLOAD 2048

struct joold_config {
	/** Is joold enabled on this Jool instance? Boolean. */
	__u8 enabled;

	/**
	 * Boolean.
	 * true:  Whenever a session changes, packet it up and send it.
	 *        (Note: In theory, this might be more often than it seems.
	 *        It's not whenever a connection is initiated;
	 *        it's on every translated packet except ICMP errors.
	 *        In practice however, flushes are prohibited until the next
	 *        ACK (otherwise joold quickly saturates the kernel), so
	 *        sessions will end up queuing up even in this mode.)
	 *        This is the preferred method in active scenarios.
	 * false: Wait until we have enough sessions to fill a packet before
	 *        sending them.
	 *        (ACKs are still required, but expected to arrive faster.)
	 *        This is the preferred method in passive scenarios.
	 */
	__u8 flush_asap;

	/**
	 * The timer forcibly flushes the queue if this hasn't happened after
	 * this amount of jiffies, regardless of the ACK and @flush_asap.
	 * This helps if an ACK is lost for some reason.
	 */
	__u64 flush_deadline;

	/**
	 * Maximim number of queuable entries.
	 * If this capacity is exceeded, Jool will have to start dropping
	 * sessions.
	 * This exists because it's theoretically possible for joold to not be
	 * able to catch up with the translating traffic, and there's not much
	 * we can do to recover if this happens.
	 */
	__u32 capacity;

	/**
	 * Maximum amount of bytes joold should send per packet, excluding
	 * IP/UDP headers.
	 *
	 * This exists because userspace joold sends sessions via UDP. UDP is
	 * rather packet-oriented, as opposed to stream-oriented, so it doesn't
	 * discover PMTU and instead tends to fragment when we send too many
	 * sessions per packet. Which is bad.
	 *
	 * So the user, after figuring out the MTU, can tweak this number to
	 * prevent fragmentation.
	 *
	 * We should probably handle this ourselves but it sounds like a lot of
	 * code. (I guess I'm missing something.)
	 */
	__u16 max_payload;
};

struct pktqueue_config {
	__u32 max_stored_pkts;
};

struct session_config {
	struct {
		__u64 tcp_est;
		__u64 tcp_trans;
		__u64 udp;
		__u64 icmp;
	} ttl;
	__u8 log_changes;
	struct pktqueue_config pktqueue;
};

struct fragdb_config {
	__u64 ttl;
};

struct full_config {
	struct global_config global;
	struct bib_config bib;
	struct session_config session;
	struct joold_config joold;
	struct fragdb_config frag;
};

struct global_value {
	__u16 type;
	/** Includes header (this) and payload. */
	__u16 len;
};

/**
 * The modes are defined by the latest version of the EAM draft.
 */
enum eam_hairpinning_mode {
	EAM_HAIRPIN_OFF = 0,
	EAM_HAIRPIN_SIMPLE = 1,
	EAM_HAIRPIN_INTRINSIC = 2,

#define EAM_HAIRPIN_MODE_COUNT 3
};

/**
 * Converts config's fields to userspace friendly units.
 */
void prepare_config_for_userspace(struct full_config *config, bool pools_empty);


#endif /* _JOOL_COMMON_CONFIG_H */
