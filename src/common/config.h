#ifndef SRC_COMMON_CONFIG_H_
#define SRC_COMMON_CONFIG_H_

/**
 * @file
 * Elements visible to both the kernel module and the userspace application, and
 * which they use to communicate with each other.
 */

#ifdef __KERNEL__
#include <net/netlink.h>
#else
#include <netlink/attr.h>
#endif
#include "common/types.h"
#include "common/xlat.h"

#define GNL_JOOL_FAMILY "Jool"
#define GNL_JOOLD_MULTICAST_GRP_NAME "joold"

/* TODO (fine) these values are not always used. */

/* Instance */
#define OPTNAME_INAME 			"instance"
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

enum jool_operation {
	JOP_INSTANCE_FOREACH,
	JOP_INSTANCE_ADD,
	JOP_INSTANCE_HELLO,
	JOP_INSTANCE_RM,
	JOP_INSTANCE_FLUSH,

	JOP_ADDRESS_QUERY64,
	JOP_ADDRESS_QUERY46,

	JOP_STATS_FOREACH,

	JOP_GLOBAL_FOREACH,
	JOP_GLOBAL_UPDATE,

	JOP_EAMT_FOREACH,
	JOP_EAMT_ADD,
	JOP_EAMT_RM,
	JOP_EAMT_FLUSH,

	JOP_BL4_FOREACH,
	JOP_BL4_ADD,
	JOP_BL4_RM,
	JOP_BL4_FLUSH,

	JOP_POOL4_FOREACH,
	JOP_POOL4_ADD,
	JOP_POOL4_RM,
	JOP_POOL4_FLUSH,

	JOP_BIB_FOREACH,
	JOP_BIB_ADD,
	JOP_BIB_RM,

	JOP_SESSION_FOREACH,

	JOP_FILE_HANDLE,

	JOP_JOOLD_ADD,
	JOP_JOOLD_TEST, /* TODO remove */
	JOP_JOOLD_ADVERTISE,
	JOP_JOOLD_ACK, /* TODO remove */
};

enum genl_mc_group_ids {
	JOOLD_MC_ID = (1 << 0),
};

enum root_attribute {
	RA_ADDR_QUERY = 1,
	RA_GLOBALS,
	RA_BL4_ENTRIES,
	RA_EAMT_ENTRIES,
	RA_POOL4_ENTRIES,
	RA_BIB_ENTRIES,
	RA_SESSION_ENTRIES,
	RA_OFFSET,
	RA_OPERAND,
	RA_PROTO,
	RA_ATOMIC_INIT,
	RA_ATOMIC_END,
	RA_COUNT,
#define RA_MAX (RA_COUNT - 1)
};

enum list_attribute {
	LA_ENTRY = 1,
	LA_COUNT,
#define LA_MAX (LA_COUNT - 1)
};

#ifdef __KERNEL__
#define ADDR6_POLICY { \
	.type = NLA_UNSPEC, \
	.len = sizeof(struct in6_addr), \
}
#define ADDR4_POLICY { \
	.type = NLA_UNSPEC, \
	.len = sizeof(struct in_addr), \
}
#else
#define ADDR6_POLICY { \
	.type = NLA_UNSPEC, \
	.minlen = sizeof(struct in6_addr), \
	.maxlen = sizeof(struct in6_addr), \
}
#define ADDR4_POLICY { \
	.type = NLA_UNSPEC, \
	.minlen = sizeof(struct in_addr), \
	.maxlen = sizeof(struct in_addr), \
}
#endif

enum prefix_attribute {
	PA_ADDR = 1,
	PA_LEN,
	PA_COUNT,
#define PA_MAX (PA_COUNT - 1)
};

extern struct nla_policy prefix6_policy[PA_COUNT];
extern struct nla_policy prefix4_policy[PA_COUNT];

enum transport_addr_attribute {
	TAA_ADDR = 1,
	TAA_PORT,
	TAA_COUNT,
#define TAA_MAX (TAA_COUNT - 1)
};

extern struct nla_policy taddr6_policy[TAA_COUNT];
extern struct nla_policy taddr4_policy[TAA_COUNT];

enum instance_entry_attribute {
	IFEA_NS = 1,
	IFEA_XF,
	IFEA_INAME,
	IFEA_COUNT,
#define IFEA_MAX (IFEA_COUNT - 1)
};

extern struct nla_policy instance_entry_policy[IFEA_COUNT];

enum instance_status_response_attribute {
	ISRA_STATUS = 1,
	ISRA_COUNT,
#define ISRA_MAX (ISRA_COUNT - 1)
};

enum instance_add_request_attribute {
	IARA_XF = 1,
	IARA_POOL6,
	IARA_COUNT,
#define IARA_MAX (IARA_COUNT - 1)
};

enum eam_attribute {
	EA_PREFIX6 = 1,
	EA_PREFIX4,
	EA_COUNT,
#define EA_MAX (EA_COUNT - 1)
};

enum pool4_attribute {
	P4A_MARK = 1,
	P4A_ITERATIONS,
	P4A_FLAGS,
	P4A_PROTO,
	P4A_PREFIX,
	P4A_PORT_MIN,
	P4A_PORT_MAX,
	P4A_COUNT,
#define P4A_MAX (P4A_COUNT - 1)
};

extern struct nla_policy pool4_entry_policy[P4A_COUNT];

enum bib_attribute {
	BA_SRC6 = 1,
	BA_SRC4,
	BA_PROTO,
	BA_STATIC,
	BA_COUNT,
#define BA_MAX (BA_COUNT - 1)
};

extern struct nla_policy bib_entry_policy[BA_COUNT];

enum session_attribute {
	SEA_SRC6 = 1,
	SEA_DST6,
	SEA_SRC4,
	SEA_DST4,
	SEA_PROTO,
	SEA_STATE,
	SEA_TIMER,
	SEA_EXPIRATION,
	SEA_COUNT,
#define SEA_MAX (SEA_COUNT - 1)
};

extern struct nla_policy session_entry_policy[SEA_COUNT];

enum address_query_attribute {
	AQA_ADDR6 = 1,
	AQA_ADDR4,
	AQA_PREFIX6052,
	AQA_EAM,
	AQA_COUNT,
#define AQA_MAX (AQA_COUNT - 1)
};

extern struct nla_policy eam_policy[EA_COUNT];

enum globals_attribute {
	/* Common */
	GA_STATUS = 1,
	GA_ENABLED,
	GA_TRACE,
	GA_POOL6,
	GA_RESET_TC,
	GA_RESET_TOS,
	GA_TOS,
	GA_PLATEAUS,

	/* SIIT */
	GA_COMPUTE_CSUM_ZERO,
	GA_HAIRPIN_MODE,
	GA_RANDOMIZE_ERROR_ADDR,
	GA_POOL6791V6,
	GA_POOL6791V4,

	/* NAT64 */
	GA_DROP_ICMP6_INFO,
	GA_SRC_ICMP6_BETTER,
	GA_F_ARGS,
	GA_HANDLE_RST,
	GA_TTL_TCP_EST,
	GA_TTL_TCP_TRANS,
	GA_TTL_UDP,
	GA_TTL_ICMP,
	GA_BIB_LOGGING,
	GA_SESSION_LOGGING,
	GA_DROP_BY_ADDR,
	GA_DROP_EXTERNAL_TCP,
	GA_MAX_STORED_PKTS,

	/* joold */
	GA_JOOLD_ENABLED,
	GA_JOOLD_FLUSH_ASAP,
	GA_JOOLD_FLUSH_DEADLINE,
	GA_JOOLD_CAPACITY,
	GA_JOOLD_MAX_PAYLOAD,

	/* Needs to be last */
	GA_COUNT,
#define GA_MAX (GA_COUNT - 1)
};

extern struct nla_policy siit_globals_policy[GA_COUNT];
extern struct nla_policy nat64_globals_policy[GA_COUNT];

enum error_attribute {
	ERRA_CODE = 1,
	ERRA_MSG,
	ERRA_COUNT,
#define ERRA_MAX (ERRA_COUNT - 1)
};

/** Is this packet an error report? */
#define HDRFLAGS_ERROR (1 << 0)
/** Ignore certain validations? */
#define HDRFLAGS_FORCE (1 << 1)
/** Cascade removal to orphaned entries? */
#define HDRFLAGS_QUICK (1 << 2)
/**
 * "Some data could not be included in this message. Please request it."
 * Named after the IPv6 fragment header flag, though it has nothing to do with
 * IP fragmentation.
 */
#define HDRFLAGS_M (1 << 3)

/**
 * Prefix to all user-to-kernel messages.
 * Indicates what the rest of the message contains.
 *
 * Mind alignment on this structure.
 *
 * (Name follows kernel conventions: iphdr, ipv6hdr, tcphdr, udphdr, icmphdr,
 * nlmsghdr, genlmsghdr)
 */
struct joolnlhdr {
	/** Jool's version. */
	__be32 version;

	/** enum xlator_type (Only relevant in requests from userspace) */
	__u8 xt;
	/** See HDRFLAGS_* above. */
	__u8 flags;

	__u8 reserved1;
	__u8 reserved2;

	char iname[INAME_MAX_SIZE];
};

void init_request_hdr(struct joolnlhdr *hdr, xlator_type xt, char const *iname,
		__u8 flags);

struct config_prefix6 {
	bool set;
	/** Please note that this could be garbage; see above. */
	struct ipv6_prefix prefix;
};

struct config_prefix4 {
	bool set;
	/** Please note that this could be garbage; see above. */
	struct ipv4_prefix prefix;
};

/**
 * Issued during atomic configuration initialization.
 */
struct request_init {
	__u8 xf; /* enum xlator_framework */
};

struct instance_entry_usr {
	/* TODO (fine) find a way to turn this into a u64? */
	__u32 ns;
	__u8 xf; /* enum xlator_framework */
	char iname[INAME_MAX_SIZE];
};

enum instance_hello_status {
	/** Instance exists */
	IHS_ALIVE,
	/** Instance does not exist */
	IHS_DEAD,
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

struct pool4_update {
	__u32 mark;
	__u32 iterations;
	__u8 flags;
	__u8 l4_proto;
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

struct bib_config {
	/* These values are always measured in milliseconds. */
	struct {
		__u32 tcp_est;
		__u32 tcp_trans;
		__u32 udp;
		__u32 icmp;
	} ttl;

	bool bib_logging;
	bool session_logging;

	/** Use Address-Dependent Filtering? */
	bool drop_by_addr;
	/** Drop externally initiated (IPv4) TCP connections? */
	bool drop_external_tcp;

	__u32 max_stored_pkts;
};

#define JOOLD_MAX_PAYLOAD 2048

struct joold_config {
	/** Is joold enabled on this Jool instance? */
	bool enabled;

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
	bool flush_asap;

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
	bool status;
	/**
	 * Does the user wants this Jool instance to translate packets?
	 */
	bool enabled;
	/** Print packet addresses on reception? */
	bool trace;

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
	bool reset_traffic_class;
	/**
	 * "true" if the Type of Service (TOS) field of translated IPv4 headers
	 * should always be set as "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class
	 * field.
	 */
	bool reset_tos;
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
			bool compute_udp_csum_zero;
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
			bool randomize_error_addresses;

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
			bool drop_icmp6_info;

			/**
			 * True = issue #132 behaviour.
			 * False = RFC 6146 behaviour.
			 */
			bool src_icmp6errs_better;
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
			bool handle_rst_during_fin_rcv;

			struct bib_config bib;
			struct joold_config joold;
		} nat64;
	};
};

/**
 * The modes are defined by the latest version of the EAM draft.
 */
enum eam_hairpinning_mode {
	EHM_OFF = 0,
	EHM_SIMPLE = 1,
	EHM_INTRINSIC = 2,
};

#endif /* SRC_COMMON_CONFIG_H_ */
