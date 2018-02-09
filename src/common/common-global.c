#include "common-global.h"

#ifdef __KERNEL__

/* Not needed in kernelspace. */

static void (*global_print_u8)(void *) = NULL;
static void (*global_print_u16)(void *) = NULL;
static void (*global_print_u32)(void *) = NULL;
static void (*global_print_plateaus)(void *) = NULL;
static void (*global_print_prefix6)(void *) = NULL;
static void (*global_print_prefix4)(void *) = NULL;
static void (*print_hairpin_mode)(void *) = NULL;

static int (*global_parse_bool)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_u8)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_u16)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_u32)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_plateaus)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_prefix6)(struct global_field *, char *, void *) = NULL;
static int (*global_parse_prefix4)(struct global_field *, char *, void *) = NULL;

#else

#include "nl-buffer.h"
#include "nl-protocol.h"
#include "usr-str-utils.h"
#include "cJSON.h"

struct global_field global_fields[];

static void global_print_bool(void *value)
{
	bool *bvalue = value;
	printf("%u", *bvalue);
}

static void global_print_u8(void *value)
{
	__u8 *uvalue = value;
	printf("%u", *uvalue);
}

static void global_print_u16(void *value)
{
	__u16 *uvalue = value;
	printf("%u", *uvalue);
}

static void global_print_u32(void *value)
{
	__u32 *uvalue = value;
	printf("%u", *uvalue);
}

static void global_print_plateaus(void *value)
{
	__u16 *uvalue;

	for (uvalue = value; *uvalue != 0; uvalue++) {
		printf("%u", *uvalue);
		if (uvalue[1] != 0)
			printf(",");
	}
}

static void print_prefix(int af, const void *addr, __u8 len, bool set)
{
	const char *str;
	char buffer[INET6_ADDRSTRLEN];

	if (!set) {
		printf("(unset)");
		return;
	}

	str = inet_ntop(af, addr, buffer, sizeof(buffer));
	if (str)
		printf("%s/%u", str, len);
	else
		perror("inet_ntop");
}

static void global_print_prefix6(void *value)
{
	struct config_prefix6 *prefix = value;
	print_prefix(AF_INET6, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set);
}

static void global_print_prefix4(void *value)
{
	struct config_prefix4 *prefix = value;
	print_prefix(AF_INET, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set);
}

static void print_hairpin_mode(void *value)
{
	switch (*((__u8 *)value)) {
	case EAM_HAIRPIN_OFF:
		printf("off");
		return;
	case EAM_HAIRPIN_SIMPLE:
		printf("simple");
		return;
	case EAM_HAIRPIN_INTRINSIC:
		printf("intrinsic");
		return;
	}

	printf("unknown");
}

static void print_fargs(void *value)
{
	__u8 uvalue = *((__u8 *)value);
	int i;

	printf("%u (0b", uvalue);
	for (i = 3; i >= 0; i--)
		printf("%u", (uvalue >> i) & 0x1);
	printf(")");
}

static int global_parse_bool(struct global_field *field, char *str, void *result)
{
	return str_to_bool(str, result);
}

static int global_parse_u8(struct global_field *field, char *str, void *result)
{
	return str_to_u8(str, result, field->min, field->max);
}

static int global_parse_u16(struct global_field *field, char *str, void *result)
{
	return str_to_u16(str, result, field->min, field->max);
}

static int global_parse_u32(struct global_field *field, char *str,
		void *result)
{
	return str_to_u32(str, result, field->min, field->max);
}

static int global_parse_plateaus(struct global_field *field, char *str,
		void *result)
{
	return str_to_plateaus_array(str, result);
}

static int global_parse_prefix6(struct global_field *field, char *str,
		void *result)
{
	struct config_prefix6 *prefix = result;

	if (strcmp(str, "null") == 0) {
		prefix->set = false;
		memset(&prefix->prefix, 0, sizeof(prefix->prefix));
		return 0;
	}

	prefix->set = true;
	return str_to_prefix6(str, &prefix->prefix);
}

static int global_parse_prefix4(struct global_field *field, char *str,
		void *result)
{
	struct config_prefix4 *prefix = result;

	if (strcmp(str, "null") == 0) {
		prefix->set = false;
		memset(&prefix->prefix, 0, sizeof(prefix->prefix));
		return 0;
	}

	prefix->set = true;
	return str_to_prefix4(str, &prefix->prefix);
}

#endif

struct global_type gt_bool = {
	.id = GTI_BOOL,
	.name = "Boolean",
	.size = sizeof(config_bool),
	.print = global_print_bool,
	.parse = global_parse_bool,
};

struct global_type gt_uint8 = {
	.id = GTI_NUM8,
	.name = "8-bit unsigned integer",
	.size = sizeof(__u8),
	.print = global_print_u8,
	.parse = global_parse_u8,
};

struct global_type gt_uint16 = {
	.id = GTI_NUM16,
	.name = "16-bit unsigned integer",
	.size = sizeof(__u16),
	.print = global_print_u16,
	.parse = global_parse_u16,
};

struct global_type gt_uint32 = {
	.id = GTI_NUM32,
	.name = "32-bit unsigned integer",
	.size = sizeof(__u32),
	.print = global_print_u32,
	.parse = global_parse_u32,
};

struct global_type gt_plateaus = {
	.id = GTI_PLATEAUS,
	.name = "List of 16-bit unsigned integers separated by commas",
	/* +1 because null-terminated. */
	.size = (PLATEAUS_MAX + 1) * sizeof(__u16),
	.print = global_print_plateaus,
	.parse = global_parse_plateaus,
};

struct global_type gt_prefix6 = {
	.id = GTI_PREFIX6,
	.name = "IPv6 prefix",
	.size = sizeof(struct config_prefix6),
	.print = global_print_prefix6,
	.parse = global_parse_prefix6,
};

struct global_type gt_prefix4 = {
	.id = GTI_PREFIX4,
	.name = "IPv4 prefix",
	.size = sizeof(struct config_prefix4),
	.print = global_print_prefix4,
	.parse = global_parse_prefix4,
};

struct global_field global_fields[] = {
	{
		.name = "zeroize-traffic-class",
		.type = &gt_bool,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
		.offset = offsetof(struct full_config, global.reset_traffic_class),
	}, {
		.name = "override-tos",
		.type = &gt_bool,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
		.offset = offsetof(struct full_config, global.reset_tos),
	}, {
		.name = "tos",
		.type = &gt_uint8,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
		.offset = offsetof(struct full_config, global.new_tos),
		.min = 0,
		.max = MAX_U8,
	}, {
		.name = "mtu-plateaus",
		.type = &gt_plateaus,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
		.offset = offsetof(struct full_config, global.mtu_plateaus),
	}, {
		.name = "address-dependent-filtering",
		.type = &gt_bool,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
		.offset = offsetof(struct full_config, bib.drop_by_addr),
	}, {
		.name = "drop-icmpv6-info",
		.type = &gt_bool,
		.doc = "Filter ICMPv6 Informational packets?",
		.offset = offsetof(struct full_config, global.drop_icmp6_info),
	}, {
		.name = "drop-externally-initiated-tcp",
		.type = &gt_bool,
		.doc = "Drop externally initiated TCP connections?",
		.offset = offsetof(struct full_config, bib.drop_external_tcp),
	}, {
		.name = "udp-timeout",
		.type = &gt_uint32,
		.doc = "Set the UDP session lifetime (in seconds).",
		.offset = offsetof(struct full_config, bib.ttl.udp),
		.min = UDP_MIN,
		.max = MAX_U32 / 1000,
	}, {
		.name = "icmp-timeout",
		.type = &gt_uint32,
		.doc = "Set the timeout for ICMP sessions (in seconds).",
		.offset = offsetof(struct full_config, bib.ttl.icmp),
		.min = 0,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-est-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP established session lifetime (in seconds).",
		.offset = offsetof(struct full_config, bib.ttl.tcp_est),
		.min = TCP_EST,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-trans-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP transitory session lifetime (in seconds).",
		.offset = offsetof(struct full_config, bib.ttl.tcp_trans),
		.min = TCP_TRANS,
		.max = MAX_U32 / 1000,
	}, {
		.name = "fragment-arrival-timeout",
		.type = &gt_uint32,
		.doc = "Set the timeout for arrival of fragments.",
		.offset = offsetof(struct full_config, frag.ttl),
		.min = FRAGMENT_MIN,
		.max = MAX_U32 / 1000,
	}, {
		.name = "maximum-simultaneous-opens",
		.type = &gt_uint32,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.",
		.offset = offsetof(struct full_config, bib.max_stored_pkts),
		.min = 0,
		.max = MAX_U32,
	}, {
		.name = "source-icmpv6-errors-better",
		.type = &gt_bool,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?",
		.offset = offsetof(struct full_config, global.src_icmp6errs_better),
	}, {
		.name = "f-args",
		.type = &gt_uint8,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.",
		.offset = offsetof(struct full_config, global.f_args),
		.min = 0,
		.max = 0x1111,
		.print = print_fargs,
	}, {
		.name = "handle-rst-during-fin-rcv",
		.type = &gt_bool,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
		.offset = offsetof(struct full_config, global.handle_rst_during_fin_rcv),
	}, {
		.name = "logging-bib",
		.type = &gt_bool,
		.doc = "Log BIBs as they are created and destroyed?",
		.offset = offsetof(struct full_config, bib.bib_logging),
	}, {
		.name = "logging-session",
		.type = &gt_bool,
		.doc = "Log sessions as they are created and destroyed?",
		.offset = offsetof(struct full_config, bib.session_logging),
	}, {
		.name = "amend-udp-checksum-zero",
		.type = &gt_bool,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.",
		.offset = offsetof(struct full_config, global.compute_udp_csum_zero),
	}, {
		.name = "eam-hairpin-mode",
		.type = &gt_uint8,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.offset = offsetof(struct full_config, global.eam_hairpin_mode),
		.min = 0,
		.max = EAM_HAIRPIN_MODE_COUNT - 1,
		.print = print_hairpin_mode,
	}, {
		.name = "randomize-rfc6791-addresses",
		.type = &gt_bool,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.",
		.offset = offsetof(struct full_config, global.randomize_error_addresses),
	}, {
		.name = "ss-enabled",
		.type = &gt_bool,
		.doc = "Enable Session Synchronization?",
		.offset = offsetof(struct full_config, joold.enabled),
	}, {
		.name = "ss-flush-asap",
		.type = &gt_bool,
		.doc = "Try to synchronize sessions as soon as possible?",
		.offset = offsetof(struct full_config, joold.flush_asap),
	}, {
		.name = "ss-flush-deadline",
		.type = &gt_uint32,
		.doc = "Inactive milliseconds after which to force a session sync.",
		.offset = offsetof(struct full_config, joold.flush_deadline),
		.min = 0,
		.max = MAX_U32,
	}, {
		.name = "ss-capacity",
		.type = &gt_uint32,
		.doc = "Maximim number of queuable entries.",
		.offset = offsetof(struct full_config, joold.capacity),
		.min = 0,
		.max = MAX_U32,
	}, {
		.name = "ss-max-payload",
		.type = &gt_uint16,
		.doc = "Maximum amount of bytes joold should send per packet.",
		.offset = offsetof(struct full_config, joold.max_payload),
		.min = 0,
		.max = JOOLD_MAX_PAYLOAD,
	}, {
		.name = "rfc6791v6-prefix",
		.type = &gt_prefix6,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.offset = offsetof(struct full_config, global.rfc6791_prefix6),
	}, {
		.name = "rfc6791v4-prefix",
		.type = &gt_prefix4,
		.doc = "IPv4 prefix to generate RFC6791 addresses from.",
		.offset = offsetof(struct full_config, global.rfc6791_prefix4),
	},
	{ 0 },
};

void get_global_fields(struct global_field **fields, unsigned int *len)
{
	*fields = global_fields;
	if (len)
		*len = (sizeof(global_fields) / sizeof(global_fields[0])) - 1;
}
