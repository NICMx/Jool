#ifndef SRC_COMMON_CONFIG_H_
#define SRC_COMMON_CONFIG_H_

/**
 * @file
 * Elements visible to both the kernel module and the userspace application, and
 * which they use to communicate with each other.
 */

#include "common/types.h"
#include "common/xlat.h"

/** cuz sizeof(bool) is implementation-defined. */
typedef __u8 config_bool;

#define IPTABLES_SIIT_MODULE_NAME "JOOL_SIIT"
#define IPTABLES_NAT64_MODULE_NAME "JOOL"

#define GNL_JOOL_FAMILY "Jool"
#define GNL_JOOLD_MULTICAST_GRP_NAME "joold"

/* TODO (fine) these values are not always used. */

/* Instance */
#define OPTNAME_INAME			"instance"
#define OPTNAME_FW			"framework"
#define OPTNAME_NETFILTER		"netfilter"
#define OPTNAME_IPTABLES		"iptables"

/* Modes */
#define OPTNAME_INSTANCE		"instance"
#define OPTNAME_ADDRESS			"address"
#define OPTNAME_STATS			"stats"
#define OPTNAME_GLOBAL			"global"
#define OPTNAME_EAMT			"eamt"
#define OPTNAME_BLACKLIST		"blacklist4"
#define OPTNAME_POOL4			"pool4"
#define OPTNAME_BIB			"bib"
#define OPTNAME_SESSION			"session"
#define OPTNAME_JOOLD			"joold"
#define OPTNAME_PARSE_FILE		"file"

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
#define OPTNAME_ENABLE			"enable"
#define OPTNAME_DISABLE			"disable"
#define OPTNAME_ZEROIZE_TC		"zeroize-traffic-class"
#define OPTNAME_OVERRIDE_TOS		"override-tos"
#define OPTNAME_TOS			"tos"
#define OPTNAME_MTU_PLATEAUS		"mtu-plateaus"
#define OPTNAME_POOL6			"pool6"

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

/* Blah */
#define OPTNAME_COMMENT			"comment"

enum genl_mc_group_ids {
	JOOLD_MC_ID = (1 << 0),
};

enum genl_commands {
	JOOL_COMMAND,
};

enum attributes {
	ATTR_DUMMY,
	ATTR_INAME,
	ATTR_DATA,
	__ATTR_MAX,
};

enum config_mode {
	/** The current message is talking about instance management. */
	MODE_INSTANCE,
	/** Querying an address translation result. */
	MODE_ADDRESS,
	/** The current message is talking about stats reporting. */
	MODE_STATS,
	/** The current message is talking about global configuration values. */
	MODE_GLOBAL,
	/** The current message is talking about the EAMT. */
	MODE_EAMT,
	/** The current message is talking about the blacklist4ed IPv4 addr pool. */
	MODE_BLACKLIST,
	/** The current message is talking about the IPv4 pool. */
	MODE_POOL4,
	/** The current message is talking about the Binding Info Bases. */
	MODE_BIB,
	/** The current message is talking about the session tables. */
	MODE_SESSION,
	/** The current message is talking about synchronization entries.*/
	MODE_JOOLD,
	/** The current message is talking about the JSON configuration file */
	MODE_PARSE_FILE,
};

char *configmode_to_string(enum config_mode mode);

enum config_operation {
	/** The userspace app wants to print the stuff being requested. */
	OP_FOREACH,
	/**
	 * The userspace app wants to add an element to the table being
	 * requested.
	 */
	OP_ADD,
	/** The userspace app wants to edit some value. */
	OP_UPDATE,
	/**
	 * The userspace app wants to delete an element from the table being
	 * requested.
	 */
	OP_REMOVE,
	/** The userspace app wants to clear some table. */
	OP_FLUSH,
	/** The userspace app wants us to shout something somewhere. */
	OP_ADVERTISE,
	/** The userspace app wants to test something. */
	OP_TEST,
	/** Somebody is acknowledging reception of a previous message. */
	OP_ACK,
};

enum parse_section {
	SEC_INIT,
	SEC_GLOBAL,
	SEC_EAMT,
	SEC_BLACKLIST,
	SEC_POOL4,
	SEC_BIB,
	/* The enum needs to fit in __u8s. */
	SEC_COMMIT = 0xFF,
};

typedef unsigned int xlator_flags;
typedef unsigned int xlator_type; /** Bitwise or'd XT_* constants below. */
typedef unsigned int xlator_framework; /** Bitwise or'd XF_* constants below. */

#define XT_SIIT (1 << 0)
#define XT_NAT64 (1 << 1)
#define XF_NETFILTER (1 << 2)
#define XF_IPTABLES (1 << 3)

#define XT_ANY (XT_SIIT | XT_NAT64)
#define XF_ANY (XF_NETFILTER | XF_IPTABLES)

int xf_validate(xlator_framework xf);
int xt_validate(xlator_type xt);

xlator_type xlator_flags2xt(xlator_flags flags);
xlator_framework xlator_flags2xf(xlator_flags flags);

#define XT_VALIDATE_ERRMSG \
	"The instance type must be either SIIT or NAT64."
#define XF_VALIDATE_ERRMSG \
	"The instance framework must be either Netfilter or iptables."

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 */
struct request_hdr {
	/** Protocol magic header (always "jool"). */
	__u8 magic[4];
	/**
	 * enum xlator_type
	 * (Only relevant in requests from userspace)
	 */
	__u8 xt;

	/**
	 * 'u'nicast or 'm'ulticast. Only userspace joold needs it, so most of
	 * the time this field is ignored.
	 *
	 * This exists because I haven't found a way for joold to tell whether a
	 * kernel packet is a multicast request or a unicast response.
	 * TODO (fine) Find a way to do that?
	 */
	__u8 castness;
	/** Ignore certain validations? */
	__u8 force;

	/**
	 * http://www.catb.org/esr/structure-packing/
	 * Explicit unused space for future functionality and to ensure
	 * sizeof(struct request_hdr) is a power of 2.
	 */
	__u8 slop1;

	/** Jool's version. */
	__be32 version;
	/** See "enum config_mode". */
	__u8 mode;
	/** See "enum config_operation". */
	__u8 operation;

	__u16 slop2;
};

void init_request_hdr(struct request_hdr *hdr, xlator_type xt,
		enum config_mode mode, enum config_operation operation,
		bool force);

/*
 * This includes the null chara; the practical maximum is 15.
 * 15 looks pallatable for decimal-thinking users :p
 */
#define INAME_MAX_LEN 16u
#define INAME_DEFAULT "default"

int iname_validate(const char *iname, bool allow_null);
#define INAME_VALIDATE_ERRMSG "The instance name must be a null-terminated ascii string, %u characters max."

struct config_prefix6 {
	config_bool set;
	/** Please note that this could be garbage; see above. */
	struct ipv6_prefix prefix;
};

struct config_prefix4 {
	config_bool set;
	/** Please note that this could be garbage; see above. */
	struct ipv4_prefix prefix;
};

struct response_hdr {
	struct request_hdr req;
	__u16 error_code;
	config_bool pending_data;
};

/**
 * Issued during atomic configuration initialization.
 */
struct request_init {
	__u8 xf; /* enum xlator_framework */
};

/* This structure needs to length a multiple of 8 bytes. */
struct instance_entry_usr {
	/* 8 */ __u64 ns;
	/* 9 */ __u8 xf; /* enum xlator_framework */
	/* 25 */ char iname[INAME_MAX_LEN];
	/* 32 */ __u8 slop[7];
};

union request_instance {
	struct {
		config_bool offset_set;
		struct instance_entry_usr offset;
	} foreach;
	struct {
		char iname[INAME_MAX_LEN];
	} hello;
	struct {
		__u8 xf; /* enum xlator_framework */
		char iname[INAME_MAX_LEN];
		struct config_prefix6 pool6;
	} add;
	struct {
		char iname[INAME_MAX_LEN];
	} rm;
};

enum instance_hello_status {
	/** Instance exists */
	IHS_ALIVE,
	/** Instance does not exist */
	IHS_DEAD,
};

struct instance_hello_response {
	__u8 status;
};

enum iteration_flags {
	/**
	 * Is the iterations field relevant?
	 * (Irrelevant = "Ignore this; keep the old value.")
	 */
	ITERATIONS_SET = (1 << 0),
	/** Should Jool compute the iterations field automatically? */
	ITERATIONS_AUTO = (1 << 1),
	/** Remove iteration cap? */
	ITERATIONS_INFINITE = (1 << 2),
};

/* This structure needs to length a multiple of 8 bytes. */
struct pool4_entry_usr {
	/* 4 */ __u32 mark;
	/**
	 * BTW: This field is only meaningful if flags has ITERATIONS_SET,
	 * !ITERATIONS_AUTO and !ITERATIONS_INFINITE.
	 */
	/* 8 */__u32 iterations;
	/* 9 */ __u8 flags;
	/* 10 */ __u8 proto;
	/* 12 */ __u16 slop;
	/* 24 */ struct ipv4_range range;
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
	} foreach;
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

union request_blacklist4 {
	struct {
		config_bool offset_set;
		struct ipv4_prefix offset;
	} foreach;
	struct {
		struct ipv4_prefix addrs;
	} add;
	struct {
		struct ipv4_prefix addrs;
	} rm;
};

/**
 * Configuration for the "EAM" module.
 */
union request_eamt {
	struct {
		config_bool prefix4_set;
		struct ipv4_prefix prefix4;
	} foreach;
	struct {
		struct ipv6_prefix prefix6;
		struct ipv4_prefix prefix4;
	} add;
	struct {
		config_bool prefix6_set;
		struct ipv6_prefix prefix6;
		config_bool prefix4_set;
		struct ipv4_prefix prefix4;
	} rm;
	struct {
		__u8 proto;
		union {
			struct in6_addr v6;
			struct in_addr v4;
		} addr;
	} test;
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
		} foreach;
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
		} foreach;
	};
};

/**
 * A BIB entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct bib_entry" and only used when BIB entries
 * need to travel to userspace. For anything else, use "struct bib_entry".
 *
 * See "struct bib_entry" for documentation on the fields.
 *
 * This structure needs to length a multiple of 8 bytes.
 */
struct bib_entry_usr {
	/* 8 */ struct ipv4_transport_addr addr4;
	/* 28 */ struct ipv6_transport_addr addr6;
	/* 29 */ __u8 l4_proto;
	/* 30 */ config_bool is_static;
	/* 32 */ __u16 slop2;
};

/**
 * A session entry, from the eyes of userspace.
 *
 * It's a stripped version of "struct session_entry" and only used when sessions
 * need to travel to userspace. For anything else, use "struct session_entry".
 *
 * See "struct session_entry" for documentation on the fields.
 *
 * This structure needs to length a multiple of 8 bytes.
 */
struct session_entry_usr {
	/* 20 */ struct ipv6_transport_addr src6;
	/* 40 */ struct ipv6_transport_addr dst6;
	/* 48 */ struct ipv4_transport_addr src4;
	/* 56 */ struct ipv4_transport_addr dst4;
	/* 57 */ __u8 state;
	/* 60 */ __u8 slop[3];
	/* 64 */ __u32 dying_time;
};

/**
 * Explicit Address Mapping definition.
 * Intended to be a row in the Explicit Address Mapping Table, bind an IPv4
 * Prefix to an IPv6 Prefix and vice versa.
 *
 * This structure needs to length a multiple of 8 bytes.
 */
struct eamt_entry {
	/* 20 */ struct ipv6_prefix prefix6;
	/* 28 */ struct ipv4_prefix prefix4;
	/* 32 */ __u32 slop;
};

struct request_addrxlat {
	int direction;
	union {
		struct in6_addr v6;
		struct in_addr v4;
	} addr;
};

enum address_translation_method {
	AXM_RFC6052,
	AXM_EAMT,
	AXM_RFC6791,
};

struct address_translation_entry {
	enum address_translation_method method;
	union {
		struct ipv6_prefix prefix6052;
		struct eamt_entry eam;
		/* The RFC6791 prefix is unused for now. */
	};
};

struct result_addrxlat64 {
	struct in_addr addr;
	struct address_translation_entry entry;
};

struct result_addrxlat46 {
	struct in6_addr addr;
	struct address_translation_entry entry;
};

enum f_args {
	F_ARGS_SRC_ADDR = (1 << 3),
	F_ARGS_SRC_PORT = (1 << 2),
	F_ARGS_DST_ADDR = (1 << 1),
	F_ARGS_DST_PORT = (1 << 0),
};

#define PLATEAUS_MAX 64

struct mtu_plateaus {
	__u16 values[PLATEAUS_MAX];
	/** Actual length of the values array. */
	__u16 count;
};

struct bib_config {
	/* These values are always measured in milliseconds. */
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
	 * this amount of milliseconds, regardless of the ACK and @flush_asap.
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
	__u32 max_payload;
};

/**
 * A copy of the entire running configuration, excluding databases.
 */
struct globals {
	/**
	 * Is Jool actually translating?
	 * This depends on several factors depending on stateness, and is not an
	 * actual variable Jool stores; it is computed as it is requested.
	 */
	config_bool status;
	/**
	 * Does the user wants this Jool instance to translate packets?
	 */
	config_bool enabled;
	/** Print packet addresses on reception? */
	config_bool trace;

	/**
	 * BTW: NAT64 Jool can't do anything without pool6, so it validates that
	 * this is this set very early. Most NAT64-exclusive code should just
	 * assume that pool6.set is true.
	 */
	struct config_prefix6 pool6;

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
	struct mtu_plateaus plateaus;

	union {
		struct {
			/**
			 * Amend the UDP checksum of incoming IPv4-UDP packets
			 * when it's zero? Otherwise these packets will be
			 * dropped (because they're illegal in IPv6).
			 */
			config_bool compute_udp_csum_zero;
			/**
			 * How should hairpinning be handled by EAM-translated
			 * packets.
			 * See @eam_hairpinning_mode.
			 */
			__u8 eam_hairpin_mode;
			/**
			 * Randomize choice of RFC6791 address?
			 * Otherwise it will be set depending on the incoming
			 * packet's Hop Limit.
			 * See https://github.com/NICMx/Jool/issues/130.
			 */
			config_bool randomize_error_addresses;

			/**
			 * Address used to represent a not translatable source
			 * address of an incoming packet.
			 */
			struct config_prefix6 rfc6791_prefix6;
			/**
			 * Address used to represent a not translatable source
			 * address of an incoming packet.
			 */
			struct config_prefix4 rfc6791_prefix4;

		} siit;
		struct {
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
			 * Decrease timer when a FIN packet is received during the
			 * `V4 FIN RCV` or `V6 FIN RCV` states?
			 * https://github.com/NICMx/Jool/issues/212
			 */
			config_bool handle_rst_during_fin_rcv;

			struct bib_config bib;
			struct joold_config joold;
		} nat64;
	};
};

struct global_value {
	__u16 type;
	/* Payload length; does not include this header. */
	__u16 len;
};

/**
 * The modes are defined by the latest version of the EAM draft.
 */
enum eam_hairpinning_mode {
	EHM_OFF = 0,
	EHM_SIMPLE = 1,
	EHM_INTRINSIC = 2,
};

/**
 * Converts config's fields to userspace friendly units.
 */
void prepare_config_for_userspace(struct globals *config, bool pools_empty);

/*
 * For iptables and nftables usage.
 *
 * This structure needs to length a multiple of 8 bytes.
 */
struct target_info {
	/* 16 */ char iname[INAME_MAX_LEN];
	/* 17 */ __u8 type; /* xlator_type */
	/* 24 */ __u8 slop[7];
};

#endif /* SRC_COMMON_CONFIG_H_ */
