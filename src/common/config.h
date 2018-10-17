#ifndef _JOOL_COMMON_CONFIG_H
#define _JOOL_COMMON_CONFIG_H

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
	ATTR_INAME,
	ATTR_DATA,
	__ATTR_MAX,
};

enum config_mode {

	MODE_INSTANCE = (1 << 11),
	/** The current message is talking about global configuration values. */
	MODE_GLOBAL = (1 << 0),
	/** The current message is talking about the IPv4 pool. */
	MODE_POOL4 = (1 << 2),
	/** The current message is talking about the blacklisted addr pool. */
	MODE_BLACKLIST = (1 << 8),
	/** The current message is talking about the RFC6791 pool. */
	MODE_RFC6791 = (1 << 7),
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
};

char *configmode_to_string(enum config_mode mode);

/**
 * @{
 * Allowed operations for the mode mentioned in the name.
 * eg. BIB_OPS = Allowed operations for BIB requests.
 */
#define DATABASE_OPS (OP_DISPLAY | OP_COUNT | OP_ADD | OP_REMOVE | OP_FLUSH)
#define ANY_OP 0xFFFF

#define GLOBAL_OPS (OP_DISPLAY | OP_UPDATE)
#define POOL4_OPS (DATABASE_OPS | OP_UPDATE)
#define BLACKLIST_OPS (DATABASE_OPS)
#define RFC6791_OPS (DATABASE_OPS)
#define EAMT_OPS (DATABASE_OPS)
#define BIB_OPS (DATABASE_OPS & ~OP_FLUSH)
#define SESSION_OPS (OP_DISPLAY | OP_COUNT)
#define JOOLD_OPS (OP_ADVERTISE | OP_TEST)
#define INSTANCE_OPS (OP_DISPLAY | OP_ADD | OP_REMOVE | OP_FLUSH)
/**
 * @}
 */

/* TODO (NOW) Do these still need to be bits? */
enum config_operation {
	/** The userspace app wants to print the stuff being requested. */
	OP_FOREACH = (1 << 0),
	/**
	 * The userspace app wants to add an element to the table being
	 * requested.
	 */
	OP_ADD = (1 << 2),
	/** The userspace app wants to edit some value. */
	OP_UPDATE = (1 << 3),
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

enum parse_section {
	SEC_GLOBAL = 1,
	SEC_POOL4 = 4,
	SEC_BIB = 8,
	SEC_COMMIT = 16,
	SEC_EAMT = 32,
	SEC_BLACKLIST = 64,
	SEC_POOL6791 = 128,
	SEC_INIT = 256
};

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
	/** Ignore certain validations? */
	__u8 force;

	/**
	 * http://www.catb.org/esr/structure-packing/
	 * Explicit unused space for future functionality and to ensure
	 * sizeof(struct request_hdr) is a power of 2.
	 */
	__u8 slop;

	/** Jool's version. */
	__be32 version;
	/** See "enum config_mode". */
	__be16 mode;
	/** See "enum config_operation". */
	__be16 operation;
};

void init_request_hdr(struct request_hdr *hdr, enum config_mode mode,
		enum config_operation operation, bool force);
int validate_request(void *data, size_t data_len, char *sender, char *receiver,
		bool *peer_is_jool);

/*
 * This includes the null chara; the practical maximum is 15.
 * 15 looks pallatable for decimal-thinking users :p
 */
#define INAME_MAX_LEN 16u
#define INAME_DEFAULT "default"

int iname_validate(const char *iname, bool allow_null);

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

#define FW_NETFILTER (1 << 0)
#define FW_IPTABLES (1 << 1)
#define FW_ANY (FW_NETFILTER | FW_IPTABLES)

int fw_validate(int fw);

/**
 * Issued during atomic configuration initialization.
 */
struct request_init {
	__u8 fw;
};

struct instance_entry_usr {
	void *ns;
	/* This is one of the FW_* constants above. */
	int fw;
	char iname[INAME_MAX_LEN];
};

union request_instance {
	struct {
		config_bool offset_set;
		struct instance_entry_usr offset;
	} display;
	struct {
		__u8 fw;
		char iname[INAME_MAX_LEN];
		struct config_prefix6 pool6;
	} add;
	struct {
		char iname[INAME_MAX_LEN];
	} rm;
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
	} add;
	struct {
		/** The addresses the user wants to remove from the pool. */
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
	} display;
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
	};
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

struct mtu_plateaus {
	__u16 values[PLATEAUS_MAX];
	/** Actual length of the values array. */
	__u16 count;
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
			 * TODO (NOW) keep this?
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

/* For iptables usage. */
struct target_info {
	char iname[INAME_MAX_LEN];
};

#endif /* _JOOL_COMMON_CONFIG_H */
