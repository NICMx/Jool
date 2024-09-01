#ifndef SRC_COMMON_TYPES_H_
#define SRC_COMMON_TYPES_H_

/**
 * @file
 * The NAT64's core data types. Structures used all over the code.
 *
 * Both the kernel module and the userspace application can see this file.
 */

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <stdbool.h>
	#include <arpa/inet.h>
#endif

/** Maximum storable value on a __u8. */
#define MAX_U8 0xFFU
/** Maximum storable value on a __u16. */
#define MAX_U16 0xFFFFU
/** Maximum storable value on a __u32. */
#define MAX_U32 0xFFFFFFFFU

typedef unsigned int xlator_flags;
typedef unsigned int xlator_type; /** Bitwise or'd XT_* constants below. */
typedef unsigned int xlator_framework; /** Bitwise or'd XF_* constants below. */

#define XT_SIIT (1 << 0)
#define XT_NAT64 (1 << 1)
#define XT_MAPT (1 << 2)
#define XT_MASK (XT_SIIT | XT_NAT64 | XT_MAPT)

#define XF_NETFILTER (1 << 3)
#define XF_IPTABLES (1 << 4)
#define XF_MASK (XF_NETFILTER | XF_IPTABLES)

#define XT_ANY XT_MASK
#define XF_ANY XF_MASK

int xf_validate(xlator_framework xf);
int xt_validate(xlator_type xt);

xlator_type xlator_flags2xt(xlator_flags flags);
xlator_framework xlator_flags2xf(xlator_flags flags);

#define XT_VALIDATE_ERRMSG \
	"The instance type must be either SIIT, NAT64 or MAP-T."

#ifdef XTABLES_DISABLED
#define XF_VALIDATE_ERRMSG \
	"Netfilter is the only available instance framework."
#else
#define XF_VALIDATE_ERRMSG \
	"Netfilter and iptables are the only available instance frameworks."
#endif

char const *xt2str(xlator_type xt);

/*
 * This includes the null chara.
 *
 * 15 looks pallatable for decimal-thinking users :p
 */
#define INAME_MAX_SIZE 16
#define INAME_DEFAULT "default"

int iname_validate(const char *iname, bool allow_null);
#define INAME_VALIDATE_ERRMSG \
	"The instance name must be a null-terminated ascii string, 15 characters max."

/**
 * Network (layer 3) protocols Jool is supposed to support.
 * We do not use PF_INET, PF_INET6, AF_INET or AF_INET6 because I want the
 * compiler to pester me during defaultless `switch`s. Also, the zero-based
 * index is convenient in the Translate Packet module.
 */
typedef enum l3_protocol {
	/** RFC 2460. */
	L3PROTO_IPV6 = 0,
	/** RFC 791. */
	L3PROTO_IPV4 = 1,
} l3_protocol;

/** Returns a string version of "proto". */
const char *l3proto_to_string(l3_protocol proto);

/**
 * Transport (layer 4) protocols Jool is supposed to support.
 * We do not use IPPROTO_TCP and friends because I want the compiler to pester
 * me during defaultless `switch`s. Also, the zero-based index is convenient in
 * the Translate Packet module.
 *
 * Please don't change the order; there's at least one for that relies on it.
 */
typedef enum l4_protocol {
	/** Signals the presence of a TCP header. */
	L4PROTO_TCP = 0,
	/** Signals the presence of a UDP header. */
	L4PROTO_UDP = 1,
	/**
	 * Signals the presence of a ICMP header. Whether the header is ICMPv4
	 * or ICMPv6 never matters.
	 * We know that ICMP is not a transport protocol, but for all intents
	 * and purposes, it behaves exactly like one in IP translation.
	 */
	L4PROTO_ICMP = 2,
	/**
	 * SIIT Jool should try to translate other protocols in a best effort
	 * basis.
	 * It will just copy layer 4 as is, and hope there's nothing to update.
	 * Because of checksumming nonsense and whatnot, this might usually
	 * fail, but whatever.
	 */
	L4PROTO_OTHER = 3,
#define L4_PROTO_COUNT 4
} l4_protocol;

/** Returns a string version of "proto". */
const char *l4proto_to_string(l4_protocol proto);
l4_protocol str_to_l4proto(char *str);

#define PLATEAUS_MAX 64

struct mtu_plateaus {
	__u16 values[PLATEAUS_MAX];
	/** Actual length of the values array. */
	__u16 count;
};

/**
 * A layer-3 (IPv4) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv4_transport_addr {
	/** The layer-3 identifier. */
	struct in_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

/* IPv4 Transport Address Prink Pattern */
#define TA4PP "%pI4#%u"
/* IPv4 Transport Address Prink Arguments */
#define TA4PA(ta) &(ta).l3, (ta).l4

/**
 * A layer-3 (IPv6) identifier attached to a layer-4 identifier.
 * Because they're paired all the time in this project.
 */
struct ipv6_transport_addr {
	/** The layer-3 identifier. */
	struct in6_addr l3;
	/** The layer-4 identifier (Either the TCP/UDP port or the ICMP id). */
	__u16 l4;
};

/* IPv6 Transport Address Prink Pattern */
#define TA6PP "%pI6c#%u"
/* IPv6 Transport Address Prink Arguments */
#define TA6PA(ta) &(ta).l3, (ta).l4

struct taddr4_tuple {
	struct ipv4_transport_addr src;
	struct ipv4_transport_addr dst;
};

/**
 * The network component of a IPv4 address.
 */
struct ipv4_prefix {
	/** IPv4 prefix. */
	struct in_addr addr;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
};

/**
 * The network component of a IPv6 address.
 */
struct ipv6_prefix {
	/** IPv6 prefix. The suffix is most of the time assumed to be zero. */
	struct in6_addr addr;
	/** Number of bits from "address" which represent the network. */
	__u8 len;
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

struct port_range {
	__u16 min;
	__u16 max;
};

struct ipv4_range {
	struct ipv4_prefix prefix;
	struct port_range ports;
};

struct pool4_entry {
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

/*
 * A mask that dictates which IPv4 transport address is being used to mask a
 * given IPv6 (transport) client.
 */
struct bib_entry {
	/** The service/client being masked. */
	struct ipv6_transport_addr addr6;
	/** The mask. */
	struct ipv4_transport_addr addr4;
	/** Protocol of the channel. */
	__u8 l4_proto;
	/** Created by userspace app client? */
	bool is_static;
};

/* BIB Entry Printk Pattern */
#define BEPP "[" TA6PP ", " TA4PP ", %s]"
/* BIB Entry Printk Arguments */
#define BEPA(b) TA6PA((b)->addr6), TA4PA((b)->addr4), \
	l4proto_to_string((b)->l4_proto)

bool port_range_equals(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_touches(const struct port_range *r1,
		const struct port_range *r2);
bool port_range_contains(const struct port_range *range, __u16 port);
unsigned int port_range_count(const struct port_range *range);
void port_range_fuse(struct port_range *r1, const struct port_range *r2);

bool ipv4_range_equals(struct ipv4_range const *r1, struct ipv4_range const *r2);
bool ipv4_range_touches(struct ipv4_range const *r1, struct ipv4_range const *r2);

/* For MAP-T */
struct mapping_rule {
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
	__u8 o; /* The EA-bits length, in bits. */

	/*
	 * Length of the Port-Restricted Port Field's "i" slice. (Also known as
	 * the "A" slice.)
	 * The RFCs have an unfortunate long name for "a": "PSID offset."
	 * In my opinion, this is a poor choice because it only makes sense if
	 * you're looking at the Port-Restricted Port Field diagram, and is very
	 * confusing if you're looking at the MAP IPv6 Address Format diagram.
	 * (`a` does not have anything to do with `n + p`.)
	 *
	 * Remember that k = q = o - p, and m = 16 - a - k.
	 * So storing those fields would be redundant.
	 *
	 * Yes, I know the RFCs imply that `a` doesn't belong to mapping rules.
	 * But let's be honest: Those RFCs are massive, massive trainwrecks.
	 * In practice, there's no reason to force all mapping rules to share
	 * the same `a`.
	 *
	 * You see, the RFCs have a massive problem in that the notion of a
	 * "MAP domain" is not consistent through them. I've decided to go with
	 * the version that makes sense to me, which is "each MAP domain has a
	 * distinct BMR." According to that definition, it doesn't make sense to
	 * force every connected MAP domain to have the same Port-Restricted
	 * Port Field.
	 */
	__u8 a;
};

__u8 maprule_get_k(struct mapping_rule *rule);

#ifdef __KERNEL__

#ifdef UNIT_TESTING
/* Exported so the unit test modules can manhandle them */
#define EXPORT_UNIT_SYMBOL(symbol) EXPORT_SYMBOL_GPL(symbol);
#define EXPORT_UNIT_STATIC
#else
#define EXPORT_UNIT_SYMBOL(symbol)
/* Static only if not exported */
#define EXPORT_UNIT_STATIC static
#endif

#else /* __KERNEL__ */

#define EXPORT_UNIT_SYMBOL(symbol)
#define EXPORT_UNIT_STATIC static

#endif

#endif /* SRC_COMMON_TYPES_H */
