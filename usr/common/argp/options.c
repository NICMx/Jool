#include "nat64/usr/argp/options.h"
#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include "nat64/usr/global.h"

static const struct argp_option targets_hdr_opt = {
		.doc = "Configuration targets/modes:",
		.group = 2,
};

static const struct argp_option pool6_opt = {
		.name = "pool6",
		.key = ARGP_POOL6,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the IPv6 prefix pool.",
		.group = 0,
};

static const struct argp_option pool4_opt = {
		.name = "pool4",
		.key = ARGP_POOL4,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the IPv4 transport address pool.",
		.group = 0,
};

static const struct argp_option bib_opt = {
		.name = "bib",
		.key = ARGP_BIB,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the BIBs.",
		.group = 0,
};

static const struct argp_option session_opt = {
		.name = "session",
		.key = ARGP_SESSION,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the session tables.",
		.group = 0,
};

static const struct argp_option joold_opt = {
		.name = "joold",
		.key = ARGP_JOOLD,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will control the kernel half of joold.",
		.group = 0,
};

static const struct argp_option eamt_opt = {
		.name = "eamt",
		.key = ARGP_EAMT,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the EAM table.",
		.group = 0,
};

static const struct argp_option blacklist_opt = {
		.name = "blacklist",
		.key = ARGP_BLACKLIST,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the IPv4 prefix blacklist.",
		.group = 0,
};

static const struct argp_option pool6791_opt = {
		.name = "pool6791",
		.key = ARGP_RFC6791,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the RFC6791 pool.",
		.group = 0,
};


#ifdef BENCHMARK
static const struct argp_option benchmark_opt = {
		.name = "logTime",
		.key = ARGP_LOGTIME,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on the logs times database.",
		.group = 0,
};
#endif

static const struct argp_option global_opt = {
		.name = "global",
		.key = ARGP_GLOBAL,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on miscellaneous "
				"configuration values (default).",
		.group = 0,
};

static const struct argp_option global_alias_opt = {
		.name = "general",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option operations_hdr_opt = {
		.doc = "Operations:",
		.group = 3,
};

static const struct argp_option instance_opt = {
		.name = "instance",
		.key = ARGP_INSTANCE,
		.arg = NULL,
		.flags = 0,
		.doc = "The command will operate on per-namespace Jool instances.",
		.group = 0,
};

static const struct argp_option display_opt = {
		.name = "display",
		.key = ARGP_DISPLAY,
		.arg = NULL,
		.flags = 0,
		.doc = "Print the target (default).",
		.group = 0,
};

static const struct argp_option count_opt = {
		.name = "count",
		.key = ARGP_COUNT,
		.arg = NULL,
		.flags = 0,
		.doc = "Print the number of elements in the target.",
		.group = 0,
};

static const struct argp_option add_opt = {
		.name = "add",
		.key = ARGP_ADD,
		.arg = NULL,
		.flags = 0,
		.doc = "Add an element to the target.",
		.group = 0,
};

static const struct argp_option update_opt = {
		.name = "update",
		.key = ARGP_UPDATE,
		.arg = NULL,
		.flags = 0,
		.doc = "Change something in the target.",
		.group = 0,
};

static const struct argp_option rm_opt = {
		.name = "remove",
		.key = ARGP_REMOVE,
		.arg = NULL,
		.flags = 0,
		.doc = "Remove an element from the target.",
		.group = 0,
};

static const struct argp_option flush_opt = {
		.name = "flush",
		.key = ARGP_FLUSH,
		.arg = NULL,
		.flags = 0,
		.doc = "Clear the target.",
		.group = 0,
};

static const struct argp_option advertise_opt = {
		.name = "advertise",
		.key = ARGP_ADVERTISE,
		.arg = NULL,
		.flags = 0,
		.doc = "Advertise the entire session DB to the multicast group.",
		.group = 0,
};

static const struct argp_option test_opt = {
		.name = "test",
		.key = ARGP_TEST,
		.arg = NULL,
		.flags = 0,
		.doc = ":>",
		.group = 0,
};

static const struct argp_option db_hdr_opt = {
		.doc = "Database miscellaneous options:",
		.group = 4,
};

static const struct argp_option quick_opt = {
		.name = "quick",
		.key = ARGP_QUICK,
		.arg = NULL,
		.flags = 0,
		.doc = "Do not clean the BIB and/or session tables after "
				"removing. Available on remove and flush "
				"operations only.",
		.group = 0,
};

static const struct argp_option mark_opt = {
		.name = "mark",
		.key = ARGP_MARK,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Only packets carrying this mark will match this pool4 "
				"entry. Available on add and remove operations "
				"only.",
		.group = 0,
};
static const struct argp_option force_opt = {
		.name = "force",
		.key = ARGP_FORCE,
		.arg = NULL,
		.flags = 0,
		.doc = "Ignore warnings.",
		.group = 0,
};

static const struct argp_option icmp_opt = {
		.name = "icmp",
		.key = ARGP_ICMP,
		.arg = NULL,
		.flags = 0,
		.doc = "Operate on the ICMP table.",
		.group = 0,
};

static const struct argp_option tcp_opt = {
		.name = "tcp",
		.key = ARGP_TCP,
		.arg = NULL,
		.flags = 0,
		.doc = "Operate on the TCP table.",
		.group = 0,
};

static const struct argp_option udp_opt = {
		.name = "udp",
		.key = ARGP_UDP,
		.arg = NULL,
		.flags = 0,
		.doc = "Operate on the UDP table.",
		.group = 0,
};

static const struct argp_option numeric_opt = {
		.name = "numeric",
		.key = ARGP_NUMERIC_HOSTNAME,
		.arg = NULL,
		.flags = 0,
		.doc = "Don't resolve names. Available on display operation "
				"only.",
		.group = 0,
};

static const struct argp_option csv_opt = {
		.name = "csv",
		.key = ARGP_CSV,
		.arg = NULL,
		.flags = 0,
		.doc = "Print in CSV format. Available on display operation "
				"only.",
		.group = 0,
};

static const struct argp_option globals_hdr_opt = {
		.doc = "'Global' options:",
		.group = 6,
};

static const struct argp_option enable_opt = {
		.name = OPTNAME_ENABLE,
		.key = ARGP_ENABLE_TRANSLATION,
		.arg = NULL,
		.flags = 0,
		.doc = "Resume translation of packets.\n",
		.group = 0,
};

static const struct argp_option disable_opt = {
		.name = OPTNAME_DISABLE,
		.key = ARGP_DISABLE_TRANSLATION,
		.arg = NULL,
		.flags = 0,
		.doc = "Pause translation of packets.\n",
		.group = 0,
};

static const struct argp_option manual_enable_opt = {
		.name = "manually-enabled",
		.key = ARGP_MANUAL_ENABLE,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Boolean version of --enable and --disable.\n",
		.group = 0,
};

static const struct argp_option zeroize_tc_opt = {
		.name = OPTNAME_ZEROIZE_TC,
		.key = ARGP_RESET_TCLASS,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Always set the IPv6 header's 'Traffic Class' field as "
				"zero? Otherwise copy from IPv4 header's "
				"'TOS'.\n",
		.group = 0,
};

static const struct argp_option zeroize_tc_alias_opt = {
		.name = "setTC",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option override_tos_opt = {
		.name = OPTNAME_OVERRIDE_TOS,
		.key = ARGP_RESET_TOS,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Override the IPv4 header's 'TOS' field as --tos? "
				"Otherwise copy from IPv6 header's "
				"'Traffic Class'.\n",
		.group = 0,
};

static const struct argp_option override_tos_alias_opt = {
		.name = "setTOS",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option tos_opt = {
		.name = OPTNAME_TOS,
		.key = ARGP_NEW_TOS,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Value to override TOS as (only when --override-tos is "
				"ON).\n",
		.group = 0,
};

static const struct argp_option tos_alias_opt = {
		.name = "TOS",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option plateaus_opt = {
		.name = OPTNAME_MTU_PLATEAUS,
		.key = ARGP_PLATEAUS,
		.arg = NUM_ARRAY_FORMAT,
		.flags = 0,
		.doc = "Set the list of plateaus for ICMPv4 Fragmentation "
				"Neededs with MTU unset.\n",
		.group = 0,
};

static const struct argp_option plateaus_alias_opt = {
		.name = "plateaus",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option adf_opt = {
		.name = OPTNAME_DROP_BY_ADDR,
		.key = ARGP_DROP_ADDR,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Use Address-Dependent Filtering? "
				"ON is (address)-restricted-cone NAT, "
				"OFF is full-cone NAT.\n",
		.group = 0,
};

static const struct argp_option adf_alias_opt = {
		.name = "dropAddr",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option icmp_filter_opt = {
		.name = OPTNAME_DROP_ICMP6_INFO,
		.key = ARGP_DROP_INFO,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Filter ICMPv6 Informational packets?\n",
		.group = 0,
};

static const struct argp_option icmp_filter_alias_opt = {
		.name = "dropInfo",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option tcp_filter_opt = {
		.name = OPTNAME_DROP_EXTERNAL_TCP,
		.key = ARGP_DROP_TCP,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Drop externally initiated TCP connections?\n",
		.group = 0,
};

static const struct argp_option tcp_filter_alias_opt = {
		.name = "dropTCP",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option ttl_udp_opt = {
		.name = OPTNAME_UDP_TIMEOUT,
		.key = ARGP_UDP_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the UDP session lifetime (in seconds).\n",
		.group = 0,
};

static const struct argp_option ttl_udp_alias_opt = {
		.name = "toUDP",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option ttl_icmp_opt = {
		.name = OPTNAME_ICMP_TIMEOUT,
		.key = ARGP_ICMP_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the timeout for ICMP sessions.\n",
		.group = 0,
};

static const struct argp_option ttl_icmp_alias_opt = {
		.name = "toICMP",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option ttl_tcpest_opt = {
		.name = OPTNAME_TCPEST_TIMEOUT,
		.key = ARGP_TCP_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the TCP established session lifetime "
				"(in seconds).\n",
		.group = 0,
};

static const struct argp_option ttl_tcpest_alias_opt = {
		.name = "toTCPest",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option ttl_tcptrans_opt = {
		.name = OPTNAME_TCPTRANS_TIMEOUT,
		.key = ARGP_TCP_TRANS_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the TCP transitory session lifetime "
				"(in seconds).\n",
		.group = 0,
};

static const struct argp_option ttl_tcptrans_alias_opt = {
		.name = "toTCPtrans",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option ttl_frag_opt = {
		.name = OPTNAME_FRAG_TIMEOUT,
		.key = ARGP_FRAG_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the timeout for arrival of fragments.\n",
		.group = 0,
};

static const struct argp_option ttl_frag_alias_opt = {
		.name = "toFrag",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option max_so_opt = {
		.name = OPTNAME_MAX_SO,
		.key = ARGP_STORED_PKTS,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the maximum allowable 'simultaneous' Simultaneos "
				"Opens of TCP connections.\n",
		.group = 0,
};

static const struct argp_option max_so_alias_opt = {
		.name = "maxStoredPkts",
		.flags = OPTION_ALIAS,
		.doc = "",
};

static const struct argp_option icmp_src_opt = {
		.name = OPTNAME_SRC_ICMP6E_BETTER,
		.key = ARGP_SRC_ICMP6ERRS_BETTER,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Translate source addresses directly on 4-to-6 ICMP "
				"errors?\n",
		.group = 0,
};

static const struct argp_option f_args_opt = {
		.name = OPTNAME_F_ARGS,
		.key = ARGP_F_ARGS,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Defines the arguments that will be sent to F().\n"
			"(F() is defined by algorithm 3 of RFC 6056.)\n"
			"- First (leftmost) bit is source address.\n"
			"- Second bit is source port.\n"
			"- Third bit is destination address.\n"
			"- Fourth (rightmost) bit is destination port.\n",
		.group = 0,
};

static const struct argp_option logging_bib_opt = {
		.name = OPTNAME_BIB_LOGGING,
		.key = ARGP_BIB_LOGGING,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Log BIBs as they are created and destroyed?\n",
		.group = 0,
};

static const struct argp_option logging_session_opt = {
		.name = OPTNAME_SESSION_LOGGING,
		.key = ARGP_SESSION_LOGGING,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Log sessions as they are created and destroyed?\n",
		.group = 0,
};

static const struct argp_option csum_fix_opt = {
		.name = OPTNAME_AMEND_UDP_CSUM,
		.key = ARGP_COMPUTE_CSUM_ZERO,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Compute the UDP checksum of IPv4-UDP packets whose "
				"value is zero? Otherwise drop the packet.\n",
		.group = 0,
};

static const struct argp_option hairpin_mode_opt = {
		.name = OPTNAME_EAM_HAIRPIN_MODE,
		.key = ARGP_EAM_HAIRPIN_MODE,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Defines how EAM+hairpinning is handled.\n"
				"(0 = Disabled; 1 = Simple; 2 = Intrinsic)",
		.group = 0,
};

static const struct argp_option random_pool6791_opt = {
		.name = OPTNAME_RANDOMIZE_RFC6791,
		.key = ARGP_RANDOMIZE_RFC6791,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Randomize selection of address from the RFC6791 pool? "
				"Otherwise choose the 'Hop Limit'th address.\n",
		.group = 0,
};

static const struct argp_option deprecated_hdr_opt = {
		.doc = "Deprecated options:",
		.group = 7,
};

static const struct argp_option atomic_frags_opt = {
		.name = OPTNAME_ALLOW_ATOMIC_FRAGS,
		.key = ARGP_ATOMIC_FRAGMENTS,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Allow atomic fragments?",
		.group = 0,
};

static const struct argp_option df_always_on_opt = {
		.name = OPTNAME_DF_ALWAYS_ON,
		.key = ARGP_DF,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Always set Don't Fragment?",
		.group = 0,
};

static const struct argp_option generate_fh_opt = {
		.name = OPTNAME_GENERATE_FH,
		.key = ARGP_BUILD_FH,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Also include IPv6 Fragment Header when IPv4 Packet DF "
				"Flag is not set?",
		.group = 0,
};

static const struct argp_option generate_id_opt = {
		.name = OPTNAME_GENERATE_ID4,
		.key = ARGP_BUILD_ID,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Generate IPv4 identification?",
		.group = 0,
};

static const struct argp_option fix_illegal_mtus_opt = {
		.name = OPTNAME_FIX_ILLEGAL_MTUS,
		.key = ARGP_LOWER_MTU_FAIL,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Decrease MTU failure rate?",
		.group = 0,
};

static const struct argp_option prefix_opt = {
		.name = "prefix",
		.key = ARGP_PREFIX,
		.arg = PREFIX6_FORMAT,
		.flags = 0,
		.doc = "Prefix to be added to or removed from the IPv6 pool. "
				"You no longer need to name this.",
		.group = 0,
};

static const struct argp_option address_opt = {
		.name = "address",
		.key = ARGP_ADDRESS,
		.arg = PREFIX4_FORMAT,
		.flags = 0,
		.doc = "Address to be added to or removed from the IPv4 pool. "
				"You no longer need to name this.",
		.group = 0,
};

static const struct argp_option bib6_opt = {
		.name = "bib6",
		.key = ARGP_BIB_IPV6,
		.arg = TRANSPORT6_FORMAT,
		.flags = 0,
		.doc = "This is the addres#port of the remote IPv6 node of "
				"the entry to be added or removed. "
				"You no longer need to name this.",
		.group = 0,
};

static const struct argp_option bib4_opt = {
		.name = "bib4",
		.key = ARGP_BIB_IPV4,
		.arg = TRANSPORT4_FORMAT,
		.flags = 0,
		.doc = "This is the local IPv4 addres#port of the entry to be "
				"added or removed. "
				"You no longer need to name this.",
		.group = 0,
};

static const struct argp_option parse_file_opt = {
		.name = "file",
		.key = ARGP_PARSE_FILE,
		.arg = "STRING",
		.flags = 0,
		.doc = "Read the configuration from a JSON file.",
		.group = 0,
};

static const struct argp_option synch_enable_opt = {
		.name = OPTNAME_SYNCH_ENABLE,
		.key = ARGP_SYNCH_ENABLE,
		.flags = 0,
		.doc = "Enables jool's synchronization mode.",
		.group = 0,
};

static const struct argp_option synch_disable_opt = {
		.name = OPTNAME_SYNCH_DISABLE,
		.key = ARGP_SYNCH_DISABLE,
		.flags = 0,
		.doc = "Disables jool's synchronization mode.",
		.group = 0,
};

static const struct argp_option synch_max_sessions_opt = {
		.name = "synch-max-sessions",
		.key = ARGP_SYNCH_MAX_SESSIONS,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Maximum number of sessions to queue in the synchronization queue before sending them to another jool server.",
		.group = 0,
};

static const struct argp_option synch_period_opt = {
		.name = "synch-period",
		.key = ARGP_SYNCH_PERIOD,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Number of milliseconds within the period timer to send sessions to another jool server.",
		.group = 0,
};

static const struct argp_option rfc6791v6_prefix_opt = {
		.name = "rfc6791v6-prefix",
		.key = ARGP_RFC6791V6_PREFIX,
		.arg = PREFIX6_FORMAT,
		.flags = 0,
		.doc = "Ipv6 prefix to be used as base for rfc6791v6 ip addresses.",
		.group = 0,
};

static const struct argp_option *opts_siit[] = {
	&targets_hdr_opt,
	&pool6_opt,
	&eamt_opt,
	&blacklist_opt,
	&pool6791_opt,
	&global_opt,
	&global_alias_opt,
#ifdef BENCHMARK
	&benchmark_opt,
#endif
	&parse_file_opt,
	&instance_opt,
	&rfc6791v6_prefix_opt,

	&operations_hdr_opt,
	&display_opt,
	&count_opt,
	&add_opt,
	&update_opt,
	&rm_opt,
	&flush_opt,

	&db_hdr_opt,
	&csv_opt,
	&force_opt,

	&globals_hdr_opt,
	&enable_opt,
	&disable_opt,
	&zeroize_tc_opt,
	&zeroize_tc_alias_opt,
	&override_tos_opt,
	&override_tos_alias_opt,
	&tos_opt,
	&tos_alias_opt,
	&plateaus_opt,
	&plateaus_alias_opt,
	&csum_fix_opt,
	&hairpin_mode_opt,
	&random_pool6791_opt,

	&deprecated_hdr_opt,
	&atomic_frags_opt,
	&df_always_on_opt,
	&generate_fh_opt,
	&generate_id_opt,
	&fix_illegal_mtus_opt,
};

static const struct argp_option *opts_nat64[] = {
	&targets_hdr_opt,
	&pool6_opt,
	&pool4_opt,
	&bib_opt,
	&session_opt,
	&joold_opt,
	&global_opt,
	&global_alias_opt,
#ifdef BENCHMARK
	&benchmark_opt,
#endif
	&parse_file_opt,
	&instance_opt,

	&operations_hdr_opt,
	&display_opt,
	&count_opt,
	&add_opt,
	&update_opt,
	&rm_opt,
	&flush_opt,
	&advertise_opt,
	&test_opt,

	&db_hdr_opt,
	&quick_opt,
	&mark_opt,
	&force_opt,
	&icmp_opt,
	&tcp_opt,
	&udp_opt,
	&numeric_opt,
	&csv_opt,

	&globals_hdr_opt,
	&enable_opt,
	&disable_opt,
	&zeroize_tc_opt,
	&zeroize_tc_alias_opt,
	&override_tos_opt,
	&override_tos_alias_opt,
	&tos_opt,
	&tos_alias_opt,
	&plateaus_opt,
	&plateaus_alias_opt,
	&adf_opt,
	&adf_alias_opt,
	&icmp_filter_opt,
	&icmp_filter_alias_opt,
	&tcp_filter_opt,
	&tcp_filter_alias_opt,
	&ttl_udp_opt,
	&ttl_udp_alias_opt,
	&ttl_icmp_opt,
	&ttl_icmp_alias_opt,
	&ttl_tcpest_opt,
	&ttl_tcpest_alias_opt,
	&ttl_tcptrans_opt,
	&ttl_tcptrans_alias_opt,
	&ttl_frag_opt,
	&ttl_frag_alias_opt,
	&max_so_opt,
	&max_so_alias_opt,
	&icmp_src_opt,
	&f_args_opt,
	&logging_bib_opt,
	&logging_session_opt,

	&deprecated_hdr_opt,
	&atomic_frags_opt,
	&df_always_on_opt,
	&generate_fh_opt,
	&generate_id_opt,
	&fix_illegal_mtus_opt,
	&prefix_opt,
	&address_opt,
	&bib6_opt,
	&bib4_opt,
	&synch_enable_opt,
	&synch_disable_opt,
	&synch_max_sessions_opt,
	&synch_period_opt,
};

struct argp_option *__build_opts(const struct argp_option **template,
		size_t template_size)
{
	struct argp_option *result;
	unsigned int size = sizeof(*result);
	unsigned int count = template_size / sizeof(*template);
	unsigned int i;

	result = malloc(size * (count + 1));
	if (!result)
		return NULL;

	for (i = 0; i < count; i++)
		memcpy(&result[i], template[i], size);
	/* Argp requirement. */
	memset(&result[count], 0, size);

	return result;
}

struct argp_option *build_opts(void)
{
	return xlat_is_siit()
			? __build_opts(opts_siit, sizeof(opts_siit))
			: __build_opts(opts_nat64, sizeof(opts_nat64));
}

static const struct argp_option *opts_global_siit[] = {
	&manual_enable_opt,
	&zeroize_tc_opt,
	&override_tos_opt,
	&tos_opt,
	&plateaus_opt,
	&csum_fix_opt,
	&hairpin_mode_opt,
	&random_pool6791_opt,
};

static const struct argp_option *opts_global_nat64[] = {
	&manual_enable_opt,
	&zeroize_tc_opt,
	&override_tos_opt,
	&tos_opt,
	&plateaus_opt,
	&adf_opt,
	&icmp_filter_opt,
	&tcp_filter_opt,
	&icmp_src_opt,
	&ttl_udp_opt,
	&ttl_icmp_opt,
	&ttl_tcpest_opt,
	&ttl_tcptrans_opt,
	&ttl_frag_opt,
	&logging_bib_opt,
	&logging_session_opt,
	&max_so_opt,
	&synch_enable_opt,
	&synch_disable_opt,
	&synch_max_sessions_opt,
	&synch_period_opt,
};

struct argp_option *get_global_opts(void)
{
	if (xlat_is_siit())
		return __build_opts(opts_global_siit, sizeof(opts_global_siit));
	return __build_opts(opts_global_nat64, sizeof(opts_global_nat64));
}
