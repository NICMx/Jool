#include "common-global.h"

#include "constants.h"

#ifdef __KERNEL__

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
#define parse_hairpin_mode NULL

int validate_u8(struct global_field *field, void *value, bool force);
int validate_u32(struct global_field *field, void *value, bool force);
int validate_pool6(struct global_field *field, void *value, bool force);
int validate_plateaus(struct global_field *field, void *value, bool force);
int validate_prefix6(struct global_field *field, void *value, bool force);
int validate_prefix4(struct global_field *field, void *value, bool force);
int validate_prefix6791v4(struct global_field *field, void *value, bool force);
int validate_hairpin_mode(struct global_field *field, void *value, bool force);

#else

void print_bool(void *value, bool csv);
void print_u8(void *value, bool csv);
void print_u32(void *value, bool csv);
void print_plateaus(void *value, bool csv);
void print_prefix6(void *value, bool csv);
void print_prefix4(void *value, bool csv);
void print_hairpin_mode(void *value, bool csv);
void print_fargs(void *value, bool csv);

int parse_bool(struct global_field *field, char *str, void *result);
int parse_u8(struct global_field *field, char *str, void *result);
int parse_u32(struct global_field *field, char *str, void *result);
int parse_plateaus(struct global_field *field, char *str, void *result);
int parse_prefix6(struct global_field *field, char *str, void *result);
int parse_prefix4(struct global_field *field, char *str, void *result);
int parse_hairpin_mode(struct global_field *field, char *str, void *result);

#define validate_u8 NULL
#define validate_u32 NULL
#define validate_pool6 NULL
#define validate_plateaus NULL
#define validate_prefix6 NULL
#define validate_prefix4 NULL
#define validate_prefix6791v4 NULL
#define validate_hairpin_mode NULL

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
	.validate = validate_u8,
};

static struct global_type gt_uint32 = {
	.id = GTI_NUM32,
	.name = "32-bit unsigned integer",
	.size = sizeof(__u32),
	.print = print_u32,
	.parse = parse_u32,
	.validate = validate_u32,
};

static struct global_type gt_plateaus = {
	.id = GTI_PLATEAUS,
	.name = "List of 16-bit unsigned integers separated by commas",
	.size = sizeof(struct mtu_plateaus),
	.print = print_plateaus,
	.parse = parse_plateaus,
	.validate = validate_plateaus,
};

static struct global_type gt_prefix6 = {
	.id = GTI_PREFIX6,
	.name = "IPv6 prefix",
	.size = sizeof(struct config_prefix6),
	.print = print_prefix6,
	.parse = parse_prefix6,
	.validate = validate_prefix6,
};

static struct global_type gt_prefix4 = {
	.id = GTI_PREFIX4,
	.name = "IPv4 prefix",
	.size = sizeof(struct config_prefix4),
	.print = print_prefix4,
	.parse = parse_prefix4,
	.validate = validate_prefix4,
};

static struct global_type gt_hairpin_mode = {
	.id = GTI_HAIRPIN_MODE,
	.name = "Hairpinning Mode",
	.size = sizeof(__u8),
	.print = print_hairpin_mode,
	.parse = parse_hairpin_mode,
	.validate = validate_hairpin_mode,
};

/* TODO constant */
static struct global_field global_fields[] = {
	{
		.name = "manually-enabled",
		.type = &gt_bool,
		.doc = "Resumes or pauses the instance's translation.",
		.offset = offsetof(struct globals, enabled),
		.xt = XT_BOTH,
	}, {
		.name = "pool6",
		.type = &gt_prefix6,
		.doc = "The IPv6 Address Pool prefix",
		.offset = offsetof(struct globals, pool6),
		.xt = XT_BOTH,
		.validate = validate_pool6,
	}, {
		.name = "zeroize-traffic-class",
		.type = &gt_bool,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as zero? Otherwise copy from IPv4 header's 'TOS'.",
		.offset = offsetof(struct globals, reset_traffic_class),
		.xt = XT_BOTH,
	}, {
		.name = "override-tos",
		.type = &gt_bool,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? Otherwise copy from IPv6 header's 'Traffic Class'.",
		.offset = offsetof(struct globals, reset_tos),
		.xt = XT_BOTH,
	}, {
		.name = "tos",
		.type = &gt_uint8,
		.doc = "Value to override TOS as (only when --override-tos is ON).",
		.offset = offsetof(struct globals, new_tos),
		.xt = XT_BOTH,
		.min = 0,
		.max = MAX_U8,
	}, {
		.name = "mtu-plateaus",
		.type = &gt_plateaus,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation Neededs with MTU unset.",
		.offset = offsetof(struct globals, plateaus),
		.xt = XT_BOTH,
	}, {
		.name = "amend-udp-checksum-zero",
		.type = &gt_bool,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose value is zero? Otherwise drop the packet.",
		.offset = offsetof(struct globals, siit.compute_udp_csum_zero),
		.xt = XT_SIIT,
	}, {
		.name = "eam-hairpin-mode",
		.type = &gt_hairpin_mode,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.offset = offsetof(struct globals, siit.eam_hairpin_mode),
		.xt = XT_SIIT,
		.min = 0,
		/* Don't mind this; the validate function will handle it. */
		.max = MAX_U8,
	}, {
		.name = "randomize-rfc6791-addresses",
		.type = &gt_bool,
		.doc = "Randomize selection of address from the RFC6791 pool? Otherwise choose the 'Hop Limit'th address.",
		.offset = offsetof(struct globals, siit.randomize_error_addresses),
		.xt = XT_SIIT,
	}, {
		.name = "pool6791v6",
		.type = &gt_prefix6,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.offset = offsetof(struct globals, siit.rfc6791_prefix6),
		.xt = XT_SIIT,
	}, {
		.name = "pool6791v4",
		.type = &gt_prefix4,
		.doc = "IPv4 prefix to generate RFC6791 addresses from.",
		.offset = offsetof(struct globals, siit.rfc6791_prefix4),
		.xt = XT_SIIT,
		.validate = validate_prefix6791v4,
	}, {
		.name = "address-dependent-filtering",
		.type = &gt_bool,
		.doc = "Use Address-Dependent Filtering? ON is (address)-restricted-cone NAT, OFF is full-cone NAT.",
		.offset = offsetof(struct globals, nat64.bib.drop_by_addr),
		.xt = XT_NAT64,
	}, {
		.name = "drop-icmpv6-info",
		.type = &gt_bool,
		.doc = "Filter ICMPv6 Informational packets?",
		.offset = offsetof(struct globals, nat64.drop_icmp6_info),
		.xt = XT_NAT64,
	}, {
		.name = "drop-externally-initiated-tcp",
		.type = &gt_bool,
		.doc = "Drop externally initiated TCP connections?",
		.offset = offsetof(struct globals, nat64.bib.drop_external_tcp),
		.xt = XT_NAT64,
	}, {
		.name = "udp-timeout",
		.type = &gt_uint32,
		.doc = "Set the UDP session lifetime (in seconds).",
		.offset = offsetof(struct globals, nat64.bib.ttl.udp),
		.xt = XT_NAT64,
		.min = UDP_MIN,
		.max = MAX_U32 / 1000,
	}, {
		.name = "icmp-timeout",
		.type = &gt_uint32,
		.doc = "Set the timeout for ICMP sessions (in seconds).",
		.offset = offsetof(struct globals, nat64.bib.ttl.icmp),
		.xt = XT_NAT64,
		.min = 0,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-est-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP established session lifetime (in seconds).",
		.offset = offsetof(struct globals, nat64.bib.ttl.tcp_est),
		.xt = XT_NAT64,
		.min = TCP_EST,
		.max = MAX_U32 / 1000,
	}, {
		.name = "tcp-trans-timeout",
		.type = &gt_uint32,
		.doc = "Set the TCP transitory session lifetime (in seconds).",
		.offset = offsetof(struct globals, nat64.bib.ttl.tcp_trans),
		.xt = XT_NAT64,
		.min = TCP_TRANS,
		.max = MAX_U32 / 1000,
	}, {
		.name = "maximum-simultaneous-opens",
		.type = &gt_uint32,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos Opens of TCP connections.",
		.offset = offsetof(struct globals, nat64.bib.max_stored_pkts),
		.min = 0,
		.max = MAX_U32,
		.xt = XT_NAT64,
	}, {
		.name = "source-icmpv6-errors-better",
		.type = &gt_bool,
		.doc = "Translate source addresses directly on 4-to-6 ICMP errors?",
		.offset = offsetof(struct globals, nat64.src_icmp6errs_better),
		.xt = XT_NAT64,
	}, {
		.name = "f-args",
		.type = &gt_uint8,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.",
		.offset = offsetof(struct globals, nat64.f_args),
		.xt = XT_NAT64,
		.min = 0,
		.max = 0b1111,
		.print = print_fargs,
	}, {
		.name = "handle-rst-during-fin-rcv",
		.type = &gt_bool,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
		.offset = offsetof(struct globals, nat64.handle_rst_during_fin_rcv),
		.xt = XT_NAT64,
	}, {
		.name = "logging-bib",
		.type = &gt_bool,
		.doc = "Log BIBs as they are created and destroyed?",
		.offset = offsetof(struct globals, nat64.bib.bib_logging),
		.xt = XT_NAT64,
	}, {
		.name = "logging-session",
		.type = &gt_bool,
		.doc = "Log sessions as they are created and destroyed?",
		.offset = offsetof(struct globals, nat64.bib.session_logging),
		.xt = XT_NAT64,
	},
	{ NULL },
};

void get_global_fields(struct global_field **fields, unsigned int *len)
{
	if (fields)
		*fields = global_fields;
	if (len)
		*len = (sizeof(global_fields) / sizeof(global_fields[0])) - 1;
}

long int global_field_index(struct global_field *field)
{
	return field - global_fields;
}
