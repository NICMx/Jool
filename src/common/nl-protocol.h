#ifndef _JOOL_COMMON_CONFIG_H
#define _JOOL_COMMON_CONFIG_H

/**
 * Elements visible to both the kernel module and the userspace application, and
 * which they use to communicate with each other.
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <uapi/linux/if.h>
#else
#include <errno.h>
#include <net/if.h>
#include <string.h>
#endif

#include "types.h"
#include "xlat.h"

/* Modes */
#define OPTNAME_GLOBAL			"global"
#define OPTNAME_POOL4			"pool4"
#define OPTNAME_EAMT			"eamt"
#define OPTNAME_BIB			"bib"
#define OPTNAME_SESSION			"session"
#define OPTNAME_PARSE_FILE		"file"
#define OPTNAME_JOOLD			"joold"
#define OPTNAME_INSTANCE		"instance"

/* Operations */
#define OPTNAME_DISPLAY			"display"
#define OPTNAME_ADD			"add"
#define OPTNAME_UPDATE			"update"
#define OPTNAME_REMOVE			"remove"
#define OPTNAME_FLUSH			"flush"
#define OPTNAME_ADVERTISE		"advertise"
#define OPTNAME_TEST			"test"
#define OPTNAME_ACK			"ack"

/* Normal flags */
#define OPTNAME_ZEROIZE_TC		"zeroize-traffic-class"
#define OPTNAME_OVERRIDE_TOS		"override-tos"
#define OPTNAME_TOS			"tos"
#define OPTNAME_MTU_PLATEAUS		"mtu-plateaus"

/* SIIT-only flags */
#define OPTNAME_AMEND_UDP_CSUM		"amend-udp-checksum-zero"
#define OPTNAME_EAM_HAIRPIN_MODE	"eam-hairpin-mode"
#define OPTNAME_RANDOMIZE_RFC6791	"randomize-rfc6791-addresses"
#define OPTNAME_RFC6791V6_PREFIX	"rfc6791v6-prefix"

/* NAT64-only flags */
#define OPTNAME_DROP_BY_ADDR		"address-dependent-filtering"
#define OPTNAME_DROP_ICMP6_INFO		"drop-icmpv6-info"
#define OPTNAME_DROP_EXTERNAL_TCP	"drop-externally-initiated-tcp"
#define OPTNAME_UDP_TIMEOUT		"udp-timeout"
#define OPTNAME_ICMP_TIMEOUT		"icmp-timeout"
#define OPTNAME_TCPEST_TIMEOUT		"tcp-est-timeout"
#define OPTNAME_TCPTRANS_TIMEOUT	"tcp-trans-timeout"
#define OPTNAME_FRAG_TIMEOUT		"fragment-arrival-timeout"
#define OPTNAME_MAX_SO			"maximum-simultaneous-opens"
#define OPTNAME_SRC_ICMP6E_BETTER	"source-icmpv6-errors-better"
#define OPTNAME_HANDLE_FIN_RCV_RST	"handle-rst-during-fin-rcv"
#define OPTNAME_F_ARGS			"f-args"
#define OPTNAME_BIB_LOGGING		"logging-bib"
#define OPTNAME_SESSION_LOGGING		"logging-session"

/* pool4 flags */
#define OPTNAME_MARK			"mark"
#define OPTNAME_MAX_ITERATIONS		"max-iterations"

/* Synchronization flags */
#define OPTNAME_SS_ENABLED		"ss-enabled"
#define OPTNAME_SS_FLUSH_ASAP		"ss-flush-asap"
#define OPTNAME_SS_FLUSH_DEADLINE	"ss-flush-deadline"
#define OPTNAME_SS_CAPACITY		"ss-capacity"
#define OPTNAME_SS_MAX_PAYLOAD		"ss-max-payload"

/** cuz sizeof(bool) is implementation-defined. */
typedef __u8 config_bool;

#define GNL_JOOL_FAMILY_NAME "Jool"
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
	/** The current message is talking about the IPv4 pool. */
	MODE_POOL4 = (1 << 2),
	/** The current message is talking about the EAMT. */
	MODE_EAMT = (1 << 6),
	/** The current message is talking about the Binding Info Bases. */
	MODE_BIB = (1 << 3),
	/** The current message is talking about the session tables. */
	MODE_SESSION = (1 << 4),
	/** The current message is talking about the JSON configuration file */
	MODE_PARSE_FILE = (1 << 9),
	/** The current message is talking about synchronization entries.*/
	MODE_JOOLD = (1 << 10),

	MODE_INSTANCE = (1 << 11),
};

char *configmode_to_string(enum config_mode mode);

/**
 * Allowed operations for the corresponding mode.
 * eg. BIB_OPS = Allowed operations for BIB requests.
 */
#define DATABASE_OPS (OP_DISPLAY | OP_ADD | OP_REMOVE | OP_FLUSH)
#define ANY_OP 0xFFFF

#define GLOBAL_OPS (OP_DISPLAY | OP_UPDATE)
#define POOL4_OPS (DATABASE_OPS | OP_UPDATE)
#define EAMT_OPS (DATABASE_OPS)
#define BIB_OPS (DATABASE_OPS & ~OP_FLUSH)
#define SESSION_OPS (OP_DISPLAY)
#define JOOLD_OPS (OP_ADVERTISE | OP_TEST)
#define INSTANCE_OPS (OP_ADD | OP_REMOVE)

enum config_operation {
	/** The userspace app wants to print the stuff being requested. */
	OP_DISPLAY = (1 << 0),
	/**
	 * The userspace app wants to add an element to the table being
	 * requested.
	 */
	OP_ADD = (1 << 3),
	/** The userspace app wants to edit some value. */
	OP_UPDATE = (1 << 2),
	/**
	 * The userspace app wants to delete an element from the table being
	 * requested.
	 */
	OP_REMOVE = (1 << 4),
	/** The userspace app wants to clear some table. */
	OP_FLUSH = (1 << 5),
	/** The userspace app wants us to shout something somewhere. */
	OP_ADVERTISE = (1 << 6),
	/** The userspace app wants to test something. */
	OP_TEST = (1 << 7),
	/** Somebody is acknowledging reception of a previous message. */
	OP_ACK = (1 << 8),
};

char *configop_to_string(enum config_operation op);

enum parse_section {
	SEC_GLOBAL = (1 << 0),
	SEC_POOL4 = (1 << 1),
	SEC_BIB = (1 << 2),
	SEC_COMMIT = (1 << 3),
	SEC_EAMT = (1 << 4),
	/* TODO change the datatype to __u8? */
	SEC_INIT = (1 << 8),
};

/**
 * Allowed modes for the corresponding operation.
 * eg. DISPLAY_MODES = Allowed modes for display operations.
 */
#define DISPLAY_MODES (MODE_GLOBAL | MODE_POOL4 | MODE_EAMT | MODE_BIB | MODE_SESSION)
#define ADD_MODES (MODE_POOL4 | MODE_EAMT | MODE_BIB | MODE_INSTANCE)
#define REMOVE_MODES (MODE_POOL4 | MODE_EAMT | MODE_BIB | MODE_INSTANCE)
#define FLUSH_MODES (MODE_POOL4 | MODE_EAMT)
#define UPDATE_MODES (MODE_GLOBAL | MODE_POOL4 | MODE_PARSE_FILE)
#define ANY_MODE 0xFFFF

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 */
struct request_hdr {
	/** Protocol magic header (always "jool"). */
	__u8 magic[4];
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
	__u8 slop[3];

	/** Jool's version. */
	__be32 version;
	/** See "enum config_mode". */
	__be16 mode;
	/** See "enum config_operation". */
	__be16 operation;
};

static inline void init_request_hdr(struct request_hdr *hdr,
		enum config_mode mode,
		enum config_operation operation)
{
	hdr->magic[0] = 'j';
	hdr->magic[1] = 'o';
	hdr->magic[2] = 'o';
	hdr->magic[3] = 'l';
	hdr->castness = 'u';
	memset(hdr->slop, 0, sizeof(hdr->slop));
	hdr->version = htonl(xlat_version());
	hdr->mode = htons(mode);
	hdr->operation = htons(operation);
}

static inline int validate_magic(struct request_hdr *hdr, char *sender)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	/* Well, the sender does not understand the protocol. */
	log_err("The %s sent a message that lacks the Jool magic text.",
			sender);
	return -EINVAL;
}

static inline int validate_version(struct request_hdr *hdr,
		char *sender, char *receiver)
{
	__u32 hdr_version = ntohl(hdr->version);

	if (xlat_version() == hdr_version)
		return 0;

	log_err("Version mismatch. The %s's version is %u.%u.%u.%u,\n"
			"but the %s is %u.%u.%u.%u.\n"
			"Please update the %s.",
			sender,
			hdr_version >> 24, (hdr_version >> 16) & 0xFFU,
			(hdr_version >> 8) & 0xFFU, hdr_version & 0xFFU,
			receiver,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr_version) ? sender : receiver);
	return -EINVAL;
}

/**
 * TODO this is a little excessive for an inline function.
 */
static inline int validate_request(void *data, size_t data_len,
		char *sender, char *receiver,
		bool *peer_is_jool)
{
	int error;

	if (peer_is_jool)
		*peer_is_jool = false;

	if (data_len < sizeof(struct request_hdr)) {
		log_err("Message from the %s is smaller than Jool's header.",
				sender);
		return -EINVAL;
	}

	error = validate_magic(data, sender);
	if (error)
		return error;

	if (peer_is_jool)
		*peer_is_jool = true;

	return validate_version(data, sender, receiver);
}

struct response_hdr {
	struct request_hdr req;
	__u16 error_code;
	config_bool pending_data;
};

union request_instance {
	char name[IFNAMSIZ];
	struct {
		__u8 type;
	} add;
};

/**
 * Configuration for the "IPv6 Pool" module.
 */
union request_pool6 {
	/** This is only relevant in display operations. */
	config_bool prefix_set;
	/** The prefix the user wants to display/add/update/remove from. */
	struct ipv6_prefix prefix;
};

enum iteration_flags {
	/**
	 * Is the iterations field relevant?
	 * (Irrelevant = "Ignore this; keep the old value.")
	 */
	ITERATIONS_SET = (1 << 0),
	/**
	 * Should Jool compute the iterations field automatically?
	 * TODO since flag 0 should be the default, this should probably be
	 * MANUAL, not AUTO.
	 */
	ITERATIONS_AUTO = (1 << 1),
	/**
	 * Remove iteration cap?
	 * TODO same here.
	 */
	ITERATIONS_INFINITE = (1 << 2),
};

struct pool4_entry_usr {
	__u32 mark;
	/**
	 * BTW: This field is only meaningful if flags has ITERATIONS_SET,
	 * !ITERATIONS_AUTO and !ITERATIONS_INFINITE.
	 */
	__u32 iterations;
	__u8 flags;
	__u8 proto;
	struct ipv4_range range;
};

struct pool4_update {
	__u32 mark;
	__u32 iterations;
	__u8 flags;
	__u8 l4_proto;
};

/**
 * Configuration for the "IPv4 Pool" module.
 */
union request_pool4 {
	struct {
		__u8 proto;
		config_bool offset_set;
		struct pool4_sample offset;
	} display;
	struct pool4_entry_usr add;
	struct pool4_update update;
	struct {
		struct pool4_entry_usr entry;
		/**
		 * Whether the address's BIB entries and sessions should be
		 * cleared too (false) or not (true).
		 */
		config_bool quick;
	} rm;
	struct {
		/**
		 * Whether the BIB and the sessions tables should also be
		 * cleared (false) or not (true).
		 */
		config_bool quick;
	} flush;
};

union request_pool {
	struct {
		config_bool offset_set;
		struct ipv4_prefix offset;
	} display;
	struct {
		/** The addresses the user wants to add to the pool. */
		struct ipv4_prefix addrs;
		/** Add @addrs even if it contains subnet-scoped addresses? */
		config_bool force;
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
		config_bool prefix4_set;
		struct ipv4_prefix prefix4;
	} display;
	struct {
		/* Nothing needed here. */
	} count;
	struct {
		struct ipv6_prefix prefix6;
		struct ipv4_prefix prefix4;
		config_bool force;
	} add;
	struct {
		config_bool prefix6_set;
		struct ipv6_prefix prefix6;
		config_bool prefix4_set;
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
			/**
			 * If this is false, this is the first chunk the app is
			 * requesting.
			 */
			config_bool iterate;
		} display;
	};
};

/**
 * Configuration for the "BIB" module.
 */
struct request_bib {
	/**
	 * Table the userspace app wants to display or edit. See enum
	 * l4_protocol.
	 */
	__u8 l4_proto;
	union {
		struct {
			config_bool addr4_set;
			/**
			 * Address the userspace app received in the last chunk.
			 * Iteration should contiue from here.
			 */
			struct ipv4_transport_addr addr4;
		} display;
		struct {
			/* Nothing needed here. */
		} count;
		struct {
			/**
			 * The IPv6 transport address of the entry the user
			 * wants to add.
			 */
			struct ipv6_transport_addr addr6;
			/**
			 * The IPv4 transport address of the entry the user
			 * wants to add.
			 */
			struct ipv4_transport_addr addr4;
		} add;
		struct {
			/* Is the value if "addr6" set? */
			config_bool addr6_set;
			/**
			 * The IPv6 transport address of the entry the user
			 * wants to remove.
			 */
			struct ipv6_transport_addr addr6;
			/* Is the value if "addr4" set? */
			config_bool addr4_set;
			/**
			 * The IPv4 transport address of the entry the user
			 * wants to remove.
			 */
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
			config_bool offset_set;
			/**
			 * Connection the userspace app received in the last
			 * chunk. Iteration should continue from here.
			 */
			struct taddr4_tuple offset;
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
	RESET_TCLASS = 1024,
	RESET_TOS,
	NEW_TOS,
	MTU_PLATEAUS,

	/* SIIT */
	COMPUTE_UDP_CSUM_ZERO,
	RANDOMIZE_RFC6791,
	EAM_HAIRPINNING_MODE,
	RFC6791V6_PREFIX,

	/* NAT64 */
	DROP_BY_ADDR,
	DROP_ICMP6_INFO,
	DROP_EXTERNAL_TCP,
	SRC_ICMP6ERRS_BETTER,
	F_ARGS,
	HANDLE_RST_DURING_FIN_RCV,
	UDP_TIMEOUT,
	ICMP_TIMEOUT,
	TCP_EST_TIMEOUT,
	TCP_TRANS_TIMEOUT,
	BIB_LOGGING,
	SESSION_LOGGING,
	MAX_PKTS,
	SS_ENABLED,
	SS_FLUSH_ASAP,
	SS_FLUSH_DEADLINE,
	SS_CAPACITY,
	SS_MAX_PAYLOAD,
};

/**
 * A BIB entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct bib_entry" and only used when BIB entries
 * need to travel to userspace. For anything else, use "struct bib_entry".
 *
 * See "struct bib_entry" for documentation on the fields.
 */
struct bib_entry_usr {
	struct ipv4_transport_addr addr4;
	struct ipv6_transport_addr addr6;
	__u8 l4_proto;
	config_bool is_static;
};

/**
 * A session entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct session_entry" and only used when sessions
 * need to travel to userspace. For anything else, use "struct session_entry".
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
struct global_config_usr {
	__u8 xlator_type;

	/** Pref64/n. In NAT64, this is the one that's usually 64:ff9b::/96. */
	struct ipv6_prefix pool6;

	/**
	 * "true" if the Traffic Class field of translated IPv6 headers should
	 * always be zeroized.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 */
	config_bool reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of translated IPv4 headers
	 * should always be set as "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class
	 * field.
	 */
	config_bool reset_tos;
	/**
	 * If "reset_tos" is "true", this is the value the translator will
	 * always write in the TOS field of translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;

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

	/******* SIIT *******/

	/**
	 * Amend the UDP checksum of incoming IPv4-UDP packets when it's zero?
	 * Otherwise these packets will be dropped (because they're illegal in
	 * IPv6).
	 */
	config_bool compute_udp_csum_zero;
	/**
	 * Randomize choice of RFC6791 address?
	 * Otherwise it will be set depending on the incoming packet's Hop
	 * Limit.
	 * See https://github.com/NICMx/Jool/issues/130.
	 */
	config_bool randomize_error_addresses;
	/**
	 * How should hairpinning be handled by EAM-translated packets.
	 * See @eam_hairpinning_mode.
	 */
	__u8 eam_hairpin_mode;
	/**
	 * States if the rfc6791_v6_prefix configuration attribute has been set.
	 * If this flag is true then the value of rfc6791_v6_prefix is going to
	 * be used.
	 */
	config_bool use_rfc6791_v6;
	/**
	 * Address used to represent a not translatable source address of an
	 * incoming packet.
	 */
	struct ipv6_prefix rfc6791_prefix6;
	config_bool use_rfc6791_v4;
	struct ipv4_prefix rfc6791_prefix4;

	/******* NAT64 *******/

	/** Filter ICMPv6 Informational packets? */
	config_bool drop_icmp6_info;
	/**
	 * True = issue #132 behaviour.
	 * False = RFC 6146 behaviour.
	 */
	config_bool src_icmp6errs_better;
	/**
	 * Fields of the packet that will be sent to the F() function.
	 * (RFC 6056 algorithm 3.)
	 * See "enum f_args".
	 */
	__u8 f_args;
	/**
	 * Decrease timer when a FIN packet is received during the `V4 FIN RCV`
	 * or `V6 FIN RCV` states?
	 * https://github.com/NICMx/Jool/issues/212
	 */
	config_bool handle_rst_during_fin_rcv;
};

struct bib_config {
	struct {
		__u32 tcp_est;
		__u32 tcp_trans;
		__u32 udp;
		__u32 icmp;
	} ttl;

	config_bool bib_logging;
	config_bool session_logging;

	/** Use Address-Dependent Filtering? */
	config_bool drop_by_addr;
	/** Drop externally initiated (IPv4) TCP connections? */
	config_bool drop_external_tcp;

	__u32 max_stored_pkts;
};

/* This has to be <= 32. */
#define JOOLD_MULTICAST_GROUP 30
#define JOOLD_MAX_PAYLOAD 2048

struct joold_config {
	/** Is joold enabled on this Jool instance? */
	config_bool enabled;

	/**
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
	config_bool flush_asap;

	/**
	 * The timer forcibly flushes the queue if this hasn't happened after
	 * this amount of jiffies, regardless of the ACK and @flush_asap.
	 * This helps if an ACK is lost for some reason.
	 */
	__u32 flush_deadline;

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

struct fragdb_config {
	__u32 ttl;
};

struct full_config {
	struct global_config_usr global;
	struct bib_config bib;
	struct joold_config joold;
	struct fragdb_config frag;
	xlator_type type;
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
void prepare_config_for_userspace(struct full_config *config);


#endif /* _JOOL_COMMON_CONFIG_H */
