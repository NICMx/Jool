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

static const struct argp_option tos_opt = {
		.name = OPTNAME_TOS,
		.key = ARGP_NEW_TOS,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Value to override TOS as (only when --override-tos is "
				"ON).\n",
		.group = 0,
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

static const struct argp_option icmp_filter_opt = {
		.name = OPTNAME_DROP_ICMP6_INFO,
		.key = ARGP_DROP_INFO,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Filter ICMPv6 Informational packets?\n",
		.group = 0,
};

static const struct argp_option tcp_filter_opt = {
		.name = OPTNAME_DROP_EXTERNAL_TCP,
		.key = ARGP_DROP_TCP,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Drop externally initiated TCP connections?\n",
		.group = 0,
};

static const struct argp_option ttl_udp_opt = {
		.name = OPTNAME_UDP_TIMEOUT,
		.key = ARGP_UDP_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the UDP session lifetime (in seconds).\n",
		.group = 0,
};

static const struct argp_option ttl_icmp_opt = {
		.name = OPTNAME_ICMP_TIMEOUT,
		.key = ARGP_ICMP_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the timeout for ICMP sessions.\n",
		.group = 0,
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

static const struct argp_option ttl_tcptrans_opt = {
		.name = OPTNAME_TCPTRANS_TIMEOUT,
		.key = ARGP_TCP_TRANS_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the TCP transitory session lifetime "
				"(in seconds).\n",
		.group = 0,
};

static const struct argp_option ttl_frag_opt = {
		.name = OPTNAME_FRAG_TIMEOUT,
		.key = ARGP_FRAG_TO,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Set the timeout for arrival of fragments.\n",
		.group = 0,
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

static const struct argp_option rst_during_fin_rcv_opt = {
		.name = OPTNAME_HANDLE_FIN_RCV_RST,
		.key = ARGP_HANDLE_RST_DURING_FIN_RCV,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Use transitory timer when RST is received during the V6 FIN RCV or V4 FIN RCV states?",
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

static const struct argp_option parse_file_opt = {
		.name = "file",
		.key = ARGP_PARSE_FILE,
		.arg = "STRING",
		.flags = 0,
		.doc = "Read the configuration from a JSON file.",
		.group = 0,
};

static const struct argp_option ss_enabled_opt = {
		.name = OPTNAME_SS_ENABLED,
		.key = ARGP_SS_ENABLED,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Enable Session Synchronization?",
		.group = 0,
};

static const struct argp_option ss_flush_asap_opt = {
		.name = OPTNAME_SS_FLUSH_ASAP,
		.key = ARGP_SS_FLUSH_ASAP,
		.arg = BOOL_FORMAT,
		.flags = 0,
		.doc = "Try to synchronize sessions as soon as possible?",
		.group = 0,
};

static const struct argp_option ss_flush_deadline_opt = {
		.name = OPTNAME_SS_FLUSH_DEADLINE,
		.key = ARGP_SS_FLUSH_DEADLINE,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Inactive milliseconds after which to force a session sync.",
		.group = 0,
};

static const struct argp_option ss_capacity_opt = {
		.name = OPTNAME_SS_CAPACITY,
		.key = ARGP_SS_CAPACITY,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Maximim number of queuable entries.",
		.group = 0,
};

static const struct argp_option ss_max_payload_opt = {
		.name = OPTNAME_SS_MAX_PAYLOAD,
		.key = ARGP_SS_MAX_PAYLOAD,
		.arg = NUM_FORMAT,
		.flags = 0,
		.doc = "Maximum amount of bytes joold should send per packet.",
		.group = 0,
};

static const struct argp_option rfc6791v6_prefix_opt = {
		.name = "rfc6791v6-prefix",
		.key = ARGP_RFC6791V6_PREFIX,
		.arg = OPTIONAL_PREFIX6_FORMAT,
		.flags = 0,
		.doc = "IPv6 prefix to generate RFC6791v6 addresses from.",
		.group = 0,
};

static const struct argp_option *opts_siit[] = {
	&targets_hdr_opt,
	&pool6_opt,
	&eamt_opt,
	&blacklist_opt,
	&pool6791_opt,
	&global_opt,
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

	&db_hdr_opt,
	&csv_opt,
	&force_opt,

	&globals_hdr_opt,
	&enable_opt,
	&disable_opt,
	&zeroize_tc_opt,
	&override_tos_opt,
	&tos_opt,
	&plateaus_opt,
	&csum_fix_opt,
	&hairpin_mode_opt,
	&random_pool6791_opt,
	&rfc6791v6_prefix_opt,
};

static const struct argp_option *opts_nat64[] = {
	&targets_hdr_opt,
	&pool6_opt,
	&pool4_opt,
	&bib_opt,
	&session_opt,
	&joold_opt,
	&global_opt,
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

	/* Globals */
	&globals_hdr_opt,
	&enable_opt,
	&disable_opt,
	&zeroize_tc_opt,
	&override_tos_opt,
	&tos_opt,
	&plateaus_opt,
	&max_so_opt,
	&icmp_src_opt,
	&f_args_opt,
	&rst_during_fin_rcv_opt,
	&logging_bib_opt,
	&logging_session_opt,
	&adf_opt,
	&icmp_filter_opt,
	&tcp_filter_opt,
	&ttl_udp_opt,
	&ttl_tcpest_opt,
	&ttl_tcptrans_opt,
	&ttl_icmp_opt,
	&ttl_frag_opt,
	&ss_enabled_opt,
	&ss_flush_asap_opt,
	&ss_flush_deadline_opt,
	&ss_capacity_opt,
	&ss_max_payload_opt,
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
	&rfc6791v6_prefix_opt,
};

static const struct argp_option *opts_global_nat64[] = {
	&manual_enable_opt,
	&zeroize_tc_opt,
	&override_tos_opt,
	&tos_opt,
	&plateaus_opt,
	&max_so_opt,
	&icmp_src_opt,
	&f_args_opt,
	&rst_during_fin_rcv_opt,
	&logging_bib_opt,
	&logging_session_opt,
	&adf_opt,
	&icmp_filter_opt,
	&tcp_filter_opt,
	&ttl_udp_opt,
	&ttl_tcpest_opt,
	&ttl_tcptrans_opt,
	&ttl_icmp_opt,
	&ttl_frag_opt,
	&ss_enabled_opt,
	&ss_flush_asap_opt,
	&ss_flush_deadline_opt,
	&ss_capacity_opt,
	&ss_max_payload_opt,
};

struct argp_option *get_global_opts(void)
{
	if (xlat_is_siit())
		return __build_opts(opts_global_siit, sizeof(opts_global_siit));
	return __build_opts(opts_global_nat64, sizeof(opts_global_nat64));
}
