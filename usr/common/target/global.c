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

static void print_allow_atomic_frags(struct global_config *conf)
{
	if (!conf->atomic_frags.df_always_on
			&& !conf->atomic_frags.build_ipv6_fh
			&& conf->atomic_frags.build_ipv4_id
			&& conf->atomic_frags.lower_mtu_fail)
		printf("OFF");

	else if (conf->atomic_frags.df_always_on
			&& conf->atomic_frags.build_ipv6_fh
			&& !conf->atomic_frags.build_ipv4_id
			&& !conf->atomic_frags.lower_mtu_fail)
		printf("ON");

	else
		printf("Mixed");
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

	printf("Status,");
	printf("Manually disabled,");
	printf(OPTNAME_ZEROIZE_TC ",");
	printf(OPTNAME_OVERRIDE_TOS ",");
	printf(OPTNAME_TOS ",");
	printf(OPTNAME_MTU_PLATEAUS ",");

	if (xlat_is_nat64()) {
		printf(OPTNAME_MAX_SO ",");
		printf(OPTNAME_SRC_ICMP6E_BETTER ",");
	} else {
		printf(OPTNAME_AMEND_UDP_CSUM ",");
		printf(OPTNAME_EAM_HAIRPIN_MODE ",");
		printf(OPTNAME_RANDOMIZE_RFC6791 ",");
	}

	printf(OPTNAME_ALLOW_ATOMIC_FRAGS ",");
	printf(OPTNAME_DF_ALWAYS_ON ",");
	printf(OPTNAME_GENERATE_FH ",");
	printf(OPTNAME_GENERATE_ID4 ",");
	printf(OPTNAME_FIX_ILLEGAL_MTUS);

	if (xlat_is_nat64()) {
		printf(",");

		printf(OPTNAME_BIB_LOGGING ",");
		printf(OPTNAME_SESSION_LOGGING ",");

		printf(OPTNAME_DROP_BY_ADDR ",");
		printf(OPTNAME_DROP_ICMP6_INFO ",");
		printf(OPTNAME_DROP_EXTERNAL_TCP ",");

		printf(OPTNAME_UDP_TIMEOUT ",");
		printf(OPTNAME_TCPEST_TIMEOUT ",");
		printf(OPTNAME_TCPTRANS_TIMEOUT ",");
		printf(OPTNAME_ICMP_TIMEOUT ",");
		printf(OPTNAME_FRAG_TIMEOUT);
	}

	printf("\n");

	printf("%s,", print_status(conf));
	printf("%s,", print_bool(conf->is_disable));
	printf("%s,", print_bool(conf->reset_traffic_class));
	printf("%s,", print_bool(conf->reset_tos));
	printf("%u,", conf->new_tos);

	printf("\"");
	print_plateaus(conf, ",");
	printf("\",");

	if (xlat_is_nat64()) {
		printf("%llu,", conf->nat64.max_stored_pkts);
		printf("%s,", print_bool(conf->nat64.src_icmp6errs_better));
	} else {
		printf("%s,", print_bool(conf->siit.compute_udp_csum_zero));
		printf("%s,", int_to_hairpin_mode(conf->siit.eam_hairpin_mode));
		printf("%s,", print_bool(conf->siit.randomize_error_addresses));
	}

	print_allow_atomic_frags(conf);
	printf(",");
	printf("%s,", print_bool(conf->atomic_frags.df_always_on));
	printf("%s,", print_bool(conf->atomic_frags.build_ipv6_fh));
	printf("%s,", print_bool(conf->atomic_frags.build_ipv4_id));
	printf("%s", print_bool(conf->atomic_frags.lower_mtu_fail));

	if (xlat_is_nat64()) {
		printf(",");

		printf("%s,", print_bool(conf->nat64.bib_logging));
		printf("%s,", print_bool(conf->nat64.session_logging));
		printf("%s,", print_bool(conf->nat64.drop_by_addr));
		printf("%s,", print_bool(conf->nat64.drop_icmp6_info));
		printf("%s,", print_bool(conf->nat64.drop_external_tcp));

		print_time_csv(conf->nat64.ttl.udp);
		printf(",");
		print_time_csv(conf->nat64.ttl.tcp_est);
		printf(",");
		print_time_csv(conf->nat64.ttl.tcp_trans);
		printf(",");
		print_time_csv(conf->nat64.ttl.icmp);
		printf(",");
		print_time_csv(conf->nat64.ttl.frag);
	}
	printf("\n");

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
