#include "nat64/usr/global.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


static char *print_status(struct global_config *conf)
{
	return conf->jool_status ? "Enabled" : "Disabled";
}

static char *print_bool(bool value)
{
	return value ? "ON" : "OFF";
}

static char *print_csv_bool(bool value)
{
	return value ? "TRUE" : "FALSE";
}

static void print_binary(unsigned int value, unsigned int size)
{
	int i;
	for (i = size - 1; i >= 0; i--)
		printf("%u", (value >> i) & 0x1);
}

static void print_plateaus(struct global_config *conf, char *separator)
{
	__u16 *plateaus;
	int i;

	plateaus = (__u16 *) (conf + 1);
	for (i = 0; i < conf->mtu_plateau_count; i++) {
		printf("%u", plateaus[i]);
		if (i != conf->mtu_plateau_count - 1)
			printf("%s", separator);
	}
}

static char *int_to_hairpin_mode(enum eam_hairpinning_mode mode)
{
	switch (mode) {
	case EAM_HAIRPIN_OFF:
		return "off";
	case EAM_HAIRPIN_SIMPLE:
		return "simple";
	case EAM_HAIRPIN_INTRINSIC:
		return "intrinsic";
	}

	return "unknown";
}

static char* print_allow_atomic_frags(struct global_config *conf)
{
	if (!conf->atomic_frags.df_always_on
			&& !conf->atomic_frags.build_ipv6_fh
			&& conf->atomic_frags.build_ipv4_id
			&& conf->atomic_frags.lower_mtu_fail)
		return "OFF";

	if (conf->atomic_frags.df_always_on
			&& conf->atomic_frags.build_ipv6_fh
			&& !conf->atomic_frags.build_ipv4_id
			&& !conf->atomic_frags.lower_mtu_fail)
		return "ON";

	return "Mixed";
}

static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct global_config *conf = nlmsg_data(nlmsg_hdr(msg));

	printf("\n");
	printf("  Status: %s\n", print_status(conf));
	printf("  Manually disabled (--%s, --%s): %s\n",
			OPTNAME_ENABLE, OPTNAME_DISABLE,
			print_bool(conf->is_disable));
	printf("\n");

	printf("  --%s: %s\n", OPTNAME_ZEROIZE_TC,
			print_bool(conf->reset_traffic_class));
	printf("  --%s: %s\n", OPTNAME_OVERRIDE_TOS,
			print_bool(conf->reset_tos));
	printf("  --%s: %u (0x%x)\n", OPTNAME_TOS,
			conf->new_tos, conf->new_tos);
	printf("  --%s:\n     ", OPTNAME_MTU_PLATEAUS);
	print_plateaus(conf, "\n     ");
	printf("\n");

	if (xlat_is_nat64()) {
		printf("  --%s: %llu\n", OPTNAME_MAX_SO,
				conf->nat64.max_stored_pkts);
		printf("  --%s: %s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_bool(conf->nat64.src_icmp6errs_better));
		printf("  --%s: %s\n", OPTNAME_HANDLE_FIN_RCV_RST,
				print_bool(conf->nat64.handle_rst_during_fin_rcv));

		printf("  --%s: %u (0b", OPTNAME_F_ARGS, conf->nat64.f_args);
		print_binary(conf->nat64.f_args, 4);
		printf(")\n");
		printf("    Src addr: %s\n", print_bool(conf->nat64.f_args & F_ARGS_SRC_ADDR));
		printf("    Src port: %s\n", print_bool(conf->nat64.f_args & F_ARGS_SRC_PORT));
		printf("    Dst addr: %s\n", print_bool(conf->nat64.f_args & F_ARGS_DST_ADDR));
		printf("    Dst port: %s\n", print_bool(conf->nat64.f_args & F_ARGS_DST_PORT));
	} else {
		printf("  --%s: %s\n", OPTNAME_AMEND_UDP_CSUM,
				print_bool(conf->siit.compute_udp_csum_zero));
		printf("  --%s: %u (%s)\n", OPTNAME_EAM_HAIRPIN_MODE,
				conf->siit.eam_hairpin_mode,
				int_to_hairpin_mode(conf->siit.eam_hairpin_mode));
		printf("  --%s: %s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_bool(conf->siit.randomize_error_addresses));
	}
	printf("\n");

	printf("  --%s: ", OPTNAME_ALLOW_ATOMIC_FRAGS);
	print_allow_atomic_frags(conf);
	printf("\n");

	printf("    --%s: %s\n", OPTNAME_DF_ALWAYS_ON,
			print_bool(conf->atomic_frags.df_always_on));
	printf("    --%s: %s\n", OPTNAME_GENERATE_FH,
			print_bool(conf->atomic_frags.build_ipv6_fh));
	printf("    --%s: %s\n", OPTNAME_GENERATE_ID4,
			print_bool(conf->atomic_frags.build_ipv4_id));
	printf("    --%s: %s\n", OPTNAME_FIX_ILLEGAL_MTUS,
			print_bool(conf->atomic_frags.lower_mtu_fail));
	printf("\n");

	if (xlat_is_nat64()) {
		printf("  Additional Logging:\n");
		printf("  --%s: %s\n", OPTNAME_BIB_LOGGING,
				print_bool(conf->nat64.bib_logging));
		printf("  --%s: %s\n", OPTNAME_SESSION_LOGGING,
				print_bool(conf->nat64.session_logging));
		printf("\n");

		printf("  Filtering:\n");
		printf("    --%s: %s\n", OPTNAME_DROP_BY_ADDR,
				print_bool(conf->nat64.drop_by_addr));
		printf("    --%s: %s\n", OPTNAME_DROP_ICMP6_INFO,
				print_bool(conf->nat64.drop_icmp6_info));
		printf("    --%s: %s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_bool(conf->nat64.drop_external_tcp));
		printf("\n");

		printf("  Timeouts:\n");
		printf("    --%s: ", OPTNAME_UDP_TIMEOUT);
		print_time_friendly(conf->nat64.ttl.udp);
		printf("    --%s: ", OPTNAME_TCPEST_TIMEOUT);
		print_time_friendly(conf->nat64.ttl.tcp_est);
		printf("    --%s: ", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_friendly(conf->nat64.ttl.tcp_trans);
		printf("    --%s: ", OPTNAME_ICMP_TIMEOUT);
		print_time_friendly(conf->nat64.ttl.icmp);
		printf("    --%s: ", OPTNAME_FRAG_TIMEOUT);
		print_time_friendly(conf->nat64.ttl.frag);
		printf("\n");
	}

	return 0;
}

static int handle_display_response_csv(struct nl_msg *msg, void *arg)
{
	struct global_config *conf = nlmsg_data(nlmsg_hdr(msg));

	printf("Status,%s\n", print_status(conf));
	printf("Manually disabled,%s\n", print_csv_bool(conf->is_disable));

	printf("%s,%s\n", OPTNAME_ZEROIZE_TC,
			print_csv_bool(conf->reset_traffic_class));
	printf("%s,%s\n", OPTNAME_OVERRIDE_TOS,
			print_csv_bool(conf->reset_tos));
	printf("%s,%u\n", OPTNAME_TOS, conf->new_tos);
	printf("%s,", OPTNAME_MTU_PLATEAUS);
	printf("\"");
	print_plateaus(conf, ",");
	printf("\"\n");

	if (xlat_is_nat64()) {
		printf("%s,%llu\n", OPTNAME_MAX_SO,
				conf->nat64.max_stored_pkts);
		printf("%s,%s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_csv_bool(conf->nat64.src_icmp6errs_better));
		printf("%s,%u\n", OPTNAME_HANDLE_FIN_RCV_RST,
				conf->nat64.handle_rst_during_fin_rcv);
		printf("%s,%u\n", OPTNAME_F_ARGS, conf->nat64.f_args);

	} else {
		printf("%s,%s\n", OPTNAME_AMEND_UDP_CSUM,
				print_csv_bool(conf->siit.compute_udp_csum_zero));
		printf("%s,%s\n", OPTNAME_EAM_HAIRPIN_MODE,
				int_to_hairpin_mode(conf->siit.eam_hairpin_mode));
		printf("%s,%s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_csv_bool(conf->siit.randomize_error_addresses));
	}

	printf("%s,%s\n", OPTNAME_ALLOW_ATOMIC_FRAGS,
			print_allow_atomic_frags(conf));
	printf("%s,%s\n", OPTNAME_DF_ALWAYS_ON,
			print_csv_bool(conf->atomic_frags.df_always_on));
	printf("%s,%s\n", OPTNAME_GENERATE_FH,
			print_csv_bool(conf->atomic_frags.build_ipv6_fh));
	printf("%s,%s\n", OPTNAME_GENERATE_ID4,
			print_csv_bool(conf->atomic_frags.build_ipv4_id));
	printf("%s,%s\n", OPTNAME_FIX_ILLEGAL_MTUS,
			print_csv_bool(conf->atomic_frags.lower_mtu_fail));

	if (xlat_is_nat64()) {
		printf("%s,%s\n", OPTNAME_BIB_LOGGING,
				print_csv_bool(conf->nat64.bib_logging));
		printf("%s,%s\n", OPTNAME_SESSION_LOGGING,
				print_csv_bool(conf->nat64.session_logging));

		printf("%s,%s\n", OPTNAME_DROP_BY_ADDR,
				print_csv_bool(conf->nat64.drop_by_addr));
		printf("%s,%s\n", OPTNAME_DROP_ICMP6_INFO,
				print_csv_bool(conf->nat64.drop_icmp6_info));
		printf("%s,%s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_csv_bool(conf->nat64.drop_external_tcp));

		printf("%s,", OPTNAME_UDP_TIMEOUT);
		print_time_csv(conf->nat64.ttl.udp);
		printf("\n%s,", OPTNAME_TCPEST_TIMEOUT);
		print_time_csv(conf->nat64.ttl.tcp_est);
		printf("\n%s,", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_csv(conf->nat64.ttl.tcp_trans);
		printf("\n%s,", OPTNAME_ICMP_TIMEOUT);
		print_time_csv(conf->nat64.ttl.icmp);
		printf("\n%s,", OPTNAME_FRAG_TIMEOUT);
		print_time_csv(conf->nat64.ttl.frag);
		printf("\n");
	}

	return 0;
}

int global_display(bool csv)
{
	struct request_hdr request;
	int (*cb)(struct nl_msg *, void *);

	init_request_hdr(&request, sizeof(request), MODE_GLOBAL, OP_DISPLAY);
	cb = csv ? handle_display_response_csv : handle_display_response;

	return netlink_request(&request, request.length, cb, NULL);
}

int global_update(__u8 type, size_t size, void *data)
{
	struct request_hdr *main_hdr;
	union request_global *global_hdr;
	void *payload;
	size_t len;
	int result;

	len = sizeof(*main_hdr) + sizeof(*global_hdr) + size;
	main_hdr = malloc(len);
	if (!main_hdr)
		return -ENOMEM;
	global_hdr = (union request_global *) (main_hdr + 1);
	payload = global_hdr + 1;

	init_request_hdr(main_hdr, len, MODE_GLOBAL, OP_UPDATE);
	global_hdr->update.type = type;
	memcpy(payload, data, size);

	result = netlink_request(main_hdr, len, NULL, NULL);
	free(main_hdr);
	return result;
}
