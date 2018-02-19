#include "common-global.h"

#include "constants.h"

#ifdef __KERNEL__

/* Not needed in kernelspace. */

#define print_bool NULL
#define print_u8 NULL
#define print_u32 NULL
#define print_plateaus NULL
#define print_prefix6 NULL
#define print_prefix4 NULL
#define print_hairpin_mode NULL
#define print_fargs NULL

#define parse_bool NULL
#define parse_u8 NULL
#define parse_u32 NULL
#define parse_plateaus NULL
#define parse_prefix6 NULL
#define parse_prefix4 NULL

#else

#include "nl-buffer.h"
#include "nl-protocol.h"
#include "usr-str-utils.h"
#include "cJSON.h"

static struct global_field global_fields[];

static void print_bool(void *value)
{
	bool *bvalue = value;
	printf("%u", *bvalue);
}

static void print_u8(void *value)
{
	__u8 *uvalue = value;
	printf("%u", *uvalue);
}

static void print_u32(void *value)
{
	__u32 *uvalue = value;
	printf("%u", *uvalue);
}

static void print_plateaus(void *value)
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

static void print_prefix6(void *value)
{
	struct config_prefix6 *prefix = value;
	print_prefix(AF_INET6, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set);
}

static void print_prefix4(void *value)
{
	struct config_prefix4 *prefix = value;
	print_prefix(AF_INET, &prefix->prefix.addr, prefix->prefix.len,
			prefix->set);
}

static void print_hairpin_mode(void *value)
{
	switch (*((__u8 *)value)) {
	case EHM_OFF:
		printf("off");
		return;
	case EHM_SIMPLE:
		printf("simple");
		return;
	case EHM_INTRINSIC:
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

static int parse_bool(struct global_field *field, char *str, void *result)
{
	return str_to_bool(str, result);
}

static int parse_u8(struct global_field *field, char *str, void *result)
{
	return str_to_u8(str, result, field->min, field->max);
}

static int parse_u32(struct global_field *field, char *str,
		void *result)
{
	return str_to_u32(str, result, field->min, field->max);
}

static int parse_plateaus(struct global_field *field, char *str,
		void *result)
{
	return str_to_plateaus_array(str, result);
}

static int parse_prefix6(struct global_field *field, char *str,
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

static int parse_prefix4(struct global_field *field, char *str,
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

static struct global_type gt_bool = {
	.id = GTI_BOOL,
	.name = "Boolean",
	.size = sizeof(config_bool),
	.print = print_bool,
	.parse = parse_bool,
};

static struct global_type gt_uint8 = {
	.id = GTI_NUM8,
	.name = "8-bit unsigned integer",
	.size = sizeof(__u8),
	.print = print_u8,
	.parse = parse_u8,
};

static struct global_type gt_uint32 = {
	.id = GTI_NUM32,
	.name = "32-bit unsigned integer",
	.size = sizeof(__u32),
	.print = print_u32,
	.parse = parse_u32,
};

static struct global_type gt_plateaus = {
	.id = GTI_PLATEAUS,
	.name = "List of 16-bit unsigned integers separated by commas",
	/* +1 because null-terminated. */
	.size = (PLATEAUS_MAX + 1) * sizeof(__u16),
	.print = print_plateaus,
	.parse = parse_plateaus,
};

static struct global_type gt_prefix6 = {
	.id = GTI_PREFIX6,
	.name = "IPv6 prefix",
	.size = sizeof(struct config_prefix6),
	.print = print_prefix6,
	.parse = parse_prefix6,
};

static struct global_type gt_prefix4 = {
	.id = GTI_PREFIX4,
	.name = "IPv4 prefix",
	.size = sizeof(struct config_prefix4),
	.print = print_prefix4,
	.parse = parse_prefix4,
};

static struct global_field global_fields[] = {
	{
		.name = "zeroize-traffic-class",
		.type = &gt_bool,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
		.offset = offsetof(struct globals, reset_traffic_class),
	}, {
		.name = "override-tos",
		.type = &gt_bool,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
		.offset = offsetof(struct globals, reset_tos),
	}, {
		.name = "tos",
		.type = &gt_uint8,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
		.offset = offsetof(struct globals, new_tos),
		.min = 0,
		.max = MAX_U8,
	}, {
		.name = "mtu-plateaus",
		.type = &gt_plateaus,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
		.offset = offsetof(struct globals, mtu_plateaus),
	}, {
		.name = "address-dependent-filtering",
		.type = &gt_bool,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
		.offset = offsetof(struct globals, bib.drop_by_addr),
	}, {
		.name = "drop-icmpv6-info",
		.type = &gt_bool,
		.doc = "Filter ICMPv6 Informational packets?",
		.offset = offsetof(struct globals, drop_icmp6_info),
	}, {
		.name = "drop-externally-initiated-tcp",
		.type = &gt_bool,
		.doc = "Drop externally initiated TCP connections?",
		.offset = offsetof(struct globals, bib.drop_external_tcp),
	}, {
		.name = "udp-timeout",
		.type = &gt_uint32,
		.doc = "Set the UDP session lifetime (in seconds).",
		.offset = offsetof(struct globals, bib.ttl.udp),
		.min = UDP_MIN,
		.max = MAX_U32 / 1000,
	}, {
		.name = "icmp-timeout",
		.type = &gt_uint32,
		.doc = "Set the timeout for ICMP sessions (in seconds).",
		.offset = offsetof(struct globals, bib.ttl.icmp),
		.min = 0,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-est-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP established session lifetime (in seconds).",
		.offset = offsetof(struct globals, bib.ttl.tcp_est),
		.min = TCP_EST,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-trans-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP transitory session lifetime (in seconds).",
		.offset = offsetof(struct globals, bib.ttl.tcp_trans),
		.min = TCP_TRANS,
		.max = MAX_U32 / 1000,
	}, {
		.name = "fragment-arrival-timeout",
		.type = &gt_uint32,
		.doc = "Set the timeout for arrival of fragments.",
		.offset = offsetof(struct globals, frag.ttl),
		.min = FRAGMENT_MIN,
		.max = MAX_U32 / 1000,
	}, {
		.name = "maximum-simultaneous-opens",
		.type = &gt_uint32,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.",
		.offset = offsetof(struct globals, bib.max_stored_pkts),
		.min = 0,
		.max = MAX_U32,
	}, {
		.name = "source-icmpv6-errors-better",
		.type = &gt_bool,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?",
		.offset = offsetof(struct globals, src_icmp6errs_better),
	}, {
		.name = "f-args",
		.type = &gt_uint8,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.",
		.offset = offsetof(struct globals, f_args),
		.min = 0,
		.max = 0x1111,
		.print = print_fargs,
	}, {
		.name = "handle-rst-during-fin-rcv",
		.type = &gt_bool,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
		.offset = offsetof(struct globals, handle_rst_during_fin_rcv),
	}, {
		.name = "logging-bib",
		.type = &gt_bool,
		.doc = "Log BIBs as they are created and destroyed?",
		.offset = offsetof(struct globals, bib.bib_logging),
	}, {
		.name = "logging-session",
		.type = &gt_bool,
		.doc = "Log sessions as they are created and destroyed?",
		.offset = offsetof(struct globals, bib.session_logging),
	}, {
		.name = "amend-udp-checksum-zero",
		.type = &gt_bool,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.",
		.offset = offsetof(struct globals, compute_udp_csum_zero),
	}, {
		.name = "eam-hairpin-mode",
		.type = &gt_uint8,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.offset = offsetof(struct globals, eam_hairpin_mode),
		.min = 0,
		.max = EHM_COUNT - 1,
		.print = print_hairpin_mode,
	}, {
		.name = "randomize-rfc6791-addresses",
		.type = &gt_bool,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.",
		.offset = offsetof(struct globals, randomize_error_addresses),
	}, {
		.name = "rfc6791v6-prefix",
		.type = &gt_prefix6,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.offset = offsetof(struct globals, rfc6791_prefix6),
	}, {
		.name = "rfc6791v4-prefix",
		.type = &gt_prefix4,
		.doc = "IPv4 prefix to generate RFC6791 addresses from.",
		.offset = offsetof(struct globals, rfc6791_prefix4),
	},
	{ NULL },
};

void get_global_fields(struct global_field **fields, unsigned int *len)
{
	*fields = global_fields;
	if (len)
		*len = (sizeof(global_fields) / sizeof(global_fields[0])) - 1;
}
