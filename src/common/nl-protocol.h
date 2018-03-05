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

#include "constants.h"
#include "types.h"
#include "xlat.h"

#define GNL_JOOL_FAMILY_NAME "Jool"

typedef enum jool_genl_cmd {
	JGNC_INSTANCE_ADD,
	JGNC_INSTANCE_RM,

	JGNC_EAMT_FOREACH,
	JGNC_EAMT_ADD,
	JGNC_EAMT_RM,
	JGNC_EAMT_FLUSH,

	JGNC_POOL4_FOREACH,
	JGNC_POOL4_ADD,
	JGNC_POOL4_RM,
	JGNC_POOL4_FLUSH,

	JGNC_BIB_FOREACH,
	JGNC_BIB_ADD,
	JGNC_BIB_RM,

	JGNC_SESSION_FOREACH,
} jool_genl_cmd;

typedef enum jool_nlattr {
	JNLA_DUMMY,

	JNLA_ERROR_MSG,

	JNLA_EAM,
	JNLA_POOL4_ENTRY,
	JNLA_BIB_ENTRY,
	JNLA_SESSION_ENTRY,

	JNLA_SADDR4, /* "Source ipv4 ADDRess" */
	JNLA_SADDR6, /* "Source ipv6 ADDRess" */
	JNLA_SPORT4, /* "Source ipv4 PORT" */
	JNLA_SPORT6, /* "Source ipv6 PORT" */
	JNLA_DADDR4, /* "Destination ipv4 ADDRess" */
	JNLA_DADDR6, /* "Destination ipv6 ADDRess" */
	JNLA_DPORT4, /* "Destination ipv4 PORT" */
	JNLA_DPORT6, /* "Destination ipv6 PORT" */

	JNLA_MINPORT,
	JNLA_MAXPORT,

	JNLA_PREFIX6ADDR,
	JNLA_PREFIX6LEN,
	JNLA_PREFIX4ADDR,
	JNLA_PREFIX4LEN,

	JNLA_L4PROTO,
	JNLA_STATIC,
	JNLA_MARK,
	JNLA_ITERATIONS,
	JNLA_ITERATION_FLAGS,
	JNLA_QUICK,
	JNLA_FORCE,
	JNLA_TCP_STATE,
	JNLA_DYING_TIME,
	JNLA_INSTANCE_NAME,
	JNLA_INSTANCE_TYPE,

	__JNLA_MAX,
} jool_nlattr;

enum parse_section {
	SEC_GLOBAL = (1 << 0),
	SEC_POOL4 = (1 << 1),
	SEC_BIB = (1 << 2),
	SEC_COMMIT = (1 << 3),
	SEC_EAMT = (1 << 4),
	/* TODO change the datatype to __u8? */
	SEC_INIT = (1 << 8),
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

typedef enum jnlmsghdr_flags {
	MF = (1 << 0),
} jnlmsghdr_flags;

/**
 * Note: This name is kind of cluttery, but it follows common kernel
 * nomenclature: iphdr, tcphdr, nlmsghdr, genlmsghdr, etc.
 */
struct jnlmsghdr {
	/** Always zero on requests, response status on responses */
	__u32 error;
	/** See jnlmsghdr_flags */
	__u32 flags;
};

/** Please always use this instead of sizeof(struct jnlmsghdr). */
#define JNL_HDR_LEN NLMSG_ALIGN(sizeof(struct jnlmsghdr))

struct pool4_entry_usr {
	__u32 mark;
	/**
	 * BTW: This field is only meaningful if flags has ITERATIONS_SET,
	 * !ITERATIONS_AUTO and !ITERATIONS_INFINITE.
	 */
	__u32 iterations;
	__u8 flags;
	l4_protocol proto;
	struct ipv4_range range;
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
	l4_protocol proto;
	bool is_static;
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
	l4_protocol proto;
	__u64 dying_time;
	tcp_state state;
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

typedef __u8 config_bool;

struct config_prefix6 {
	/** Meat. */
	struct ipv6_prefix prefix;
	/** Is @prefix set? */
	config_bool set;
};

struct config_prefix4 {
	/** Meat. */
	struct ipv4_prefix prefix;
	/** Is @prefix set? */
	config_bool set;
};

#define PLATEAUS_MAX 63

struct globals_bib {
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

struct globals_fragdb {
	__u32 ttl;
};

struct globals_joold {
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

/*
 * By the way: There's code out there that assumes that there are no pointer
 * fields in this structure.
 */
struct globals {
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
	 *
	 * The array is zero-terminated.
	 */
	__u16 mtu_plateaus[PLATEAUS_MAX + 1];

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
	 * How should hairpinning be handled for EAM-translated packets.
	 * See @eam_hairpinning_mode.
	 */
	__u8 eam_hairpin_mode;

	/** Addresses for sourcing ICMP errors with untranslatable addresses. */
	struct config_prefix6 rfc6791_prefix6;
	struct config_prefix4 rfc6791_prefix4;

	/******* NAT64 *******/

	/** Filter ICMPv6 Informational packets? */
	config_bool drop_icmp6_info;
	/**
	 * True = issue #132 behaviour.
	 * False = RFC 6146 behaviour.
	 * https://github.com/NICMx/Jool/issues/132
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

	struct globals_bib bib;
	struct globals_fragdb frag;
	struct globals_joold joold;
};

/* This has to be <= 32. */
#define JOOLD_MULTICAST_GROUP 30 /* TODO not used */
#define JOOLD_MAX_PAYLOAD 2048 /* TODO doc */

struct request_global_update {
	__u16 type;
	/* Value hangs-off here. */
};

/**
 * See RFC 7757 section 4.2.
 */
typedef enum eam_hairpinning_mode {
	EHM_OFF = 0,
	EHM_SIMPLE = 1,
	EHM_INTRINSIC = 2,

#define EHM_COUNT 3
} eam_hairpinning_mode;

/**
 * Converts config's fields to userspace friendly units.
 */
void prepare_config_for_userspace(struct globals *config);


#endif /* _JOOL_COMMON_CONFIG_H */
