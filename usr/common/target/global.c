#include "nat64/usr/global.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


static char *print_status(struct global_config *conf)
{
	return conf->status ? "Enabled" : "Disabled";
}

static char *print_bool(bool value)
{
	return value ? "ON" : "OFF";
}

static void print_plateaus(struct global_config *conf, char *separator)
{
	int i;

	for (i = 0; i < conf->mtu_plateau_count; i++) {
		printf("%u", conf->mtu_plateaus[i]);
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

static int handle_display_response(struct jool_response *response, void *arg)
{
	struct full_config *conf = response->payload;

	if (response->payload_len != sizeof(struct full_config)) {
		log_err("Jool's response is not a structure containing global values.");
		return -EINVAL;
	}

	printf("\n");
	printf("  Status: %s\n", print_status(&conf->global));
	printf("  Manually enabled (--%s, --%s): %s\n",
			OPTNAME_ENABLE, OPTNAME_DISABLE,
			print_bool(conf->global.enabled));
	printf("\n");

	printf("  --%s: %s\n", OPTNAME_ZEROIZE_TC,
			print_bool(conf->global.reset_traffic_class));
	printf("  --%s: %s\n", OPTNAME_OVERRIDE_TOS,
			print_bool(conf->global.reset_tos));
	printf("  --%s: %u (0x%x)\n", OPTNAME_TOS,
			conf->global.new_tos, conf->global.new_tos);
	printf("  --%s:\n     ", OPTNAME_MTU_PLATEAUS);
	print_plateaus(&conf->global, "\n     ");
	printf("\n");

	if (xlat_is_nat64()) {
		printf("  --%s: %u\n", OPTNAME_MAX_SO,
				conf->session.pktqueue.max_stored_pkts);
		printf("  --%s: %s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_bool(conf->global.nat64.src_icmp6errs_better));
	} else {
		printf("  --%s: %s\n", OPTNAME_AMEND_UDP_CSUM,
				print_bool(conf->global.siit.compute_udp_csum_zero));
		printf("  --%s: %u (%s)\n", OPTNAME_EAM_HAIRPIN_MODE,
				conf->global.siit.eam_hairpin_mode,
				int_to_hairpin_mode(conf->global.siit.eam_hairpin_mode));
		printf("  --%s: %s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_bool(conf->global.siit.randomize_error_addresses));
	}
	printf("\n");

	printf("  --%s: ", OPTNAME_ALLOW_ATOMIC_FRAGS);
	print_allow_atomic_frags(&conf->global);
	printf("\n");

	printf("    --%s: %s\n", OPTNAME_DF_ALWAYS_ON,
			print_bool(conf->global.atomic_frags.df_always_on));
	printf("    --%s: %s\n", OPTNAME_GENERATE_FH,
			print_bool(conf->global.atomic_frags.build_ipv6_fh));
	printf("    --%s: %s\n", OPTNAME_GENERATE_ID4,
			print_bool(conf->global.atomic_frags.build_ipv4_id));
	printf("    --%s: %s\n", OPTNAME_FIX_ILLEGAL_MTUS,
			print_bool(conf->global.atomic_frags.lower_mtu_fail));
	printf("\n");

	if (xlat_is_nat64()) {
		printf("  Additional Logging:\n");
		printf("  --%s: %s\n", OPTNAME_BIB_LOGGING,
				print_bool(conf->bib.log_changes));
		printf("  --%s: %s\n", OPTNAME_SESSION_LOGGING,
				print_bool(conf->session.log_changes));
		printf("\n");

		printf("  Filtering:\n");
		printf("    --%s: %s\n", OPTNAME_DROP_BY_ADDR,
				print_bool(conf->global.nat64.drop_by_addr));
		printf("    --%s: %s\n", OPTNAME_DROP_ICMP6_INFO,
				print_bool(conf->global.nat64.drop_icmp6_info));
		printf("    --%s: %s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_bool(conf->global.nat64.drop_external_tcp));
		printf("\n");

		printf("  Timeouts:\n");
		printf("    --%s: ", OPTNAME_UDP_TIMEOUT);
		print_time_friendly(conf->session.ttl.udp);
		printf("    --%s: ", OPTNAME_TCPEST_TIMEOUT);
		print_time_friendly(conf->session.ttl.tcp_est);
		printf("    --%s: ", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_friendly(conf->session.ttl.tcp_trans);
		printf("    --%s: ", OPTNAME_ICMP_TIMEOUT);
		print_time_friendly(conf->session.ttl.icmp);
		printf("    --%s: ", OPTNAME_FRAG_TIMEOUT);
		print_time_friendly(conf->global.nat64.ttl.frag);
		printf("\n");

		printf("  Synchronization:\n");
		printf("  Enabled (--%s, --%s): %s\n",
				OPTNAME_SYNCH_ENABLE , OPTNAME_SYNCH_DISABLE,
				conf->session.joold.enabled ? "Enabled" : "Disabled");

		printf("    --%s: %u sessions\n", OPTNAME_SYNCH_MAX_SESSIONS, conf->session.joold.queue_capacity);
		printf("    --%s: %u milliseconds\n", OPTNAME_SYNCH_PERIOD, conf->session.joold.timer_period);
	}

	return 0;
}

static int handle_display_response_csv(struct jool_response *response, void *arg)
{
	struct full_config *conf = response->payload;

	if (response->payload_len != sizeof(struct full_config)) {
		log_err("Jool's response is not a structure containing global values.");
		return -EINVAL;
	}

	printf("Status,");
	printf("Manually enabled,");
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
		printf(OPTNAME_FRAG_TIMEOUT",");

		printf("Synchronization Status,");
		printf(OPTNAME_SYNCH_MAX_SESSIONS ",");
		printf(OPTNAME_SYNCH_PERIOD ",");
	}

	printf("\n");

	printf("%s,", print_status(&conf->global));
	printf("%s,", print_bool(conf->global.enabled));
	printf("%s,", print_bool(conf->global.reset_traffic_class));
	printf("%s,", print_bool(conf->global.reset_tos));
	printf("%u,", conf->global.new_tos);

	printf("\"");
	print_plateaus(&conf->global, ",");
	printf("\",");

	if (xlat_is_nat64()) {
		printf("%u,", conf->session.pktqueue.max_stored_pkts);
		printf("%s,", print_bool(conf->global.nat64.src_icmp6errs_better));
	} else {
		printf("%s,", print_bool(conf->global.siit.compute_udp_csum_zero));
		printf("%s,", int_to_hairpin_mode(conf->global.siit.eam_hairpin_mode));
		printf("%s,", print_bool(conf->global.siit.randomize_error_addresses));
	}

	print_allow_atomic_frags(&conf->global);
	printf(",");
	printf("%s,", print_bool(conf->global.atomic_frags.df_always_on));
	printf("%s,", print_bool(conf->global.atomic_frags.build_ipv6_fh));
	printf("%s,", print_bool(conf->global.atomic_frags.build_ipv4_id));
	printf("%s", print_bool(conf->global.atomic_frags.lower_mtu_fail));

	if (xlat_is_nat64()) {
		printf(",");

		printf("%s,", print_bool(conf->bib.log_changes));
		printf("%s,", print_bool(conf->session.log_changes));
		printf("%s,", print_bool(conf->global.nat64.drop_by_addr));
		printf("%s,", print_bool(conf->global.nat64.drop_icmp6_info));
		printf("%s,", print_bool(conf->global.nat64.drop_external_tcp));

		print_time_csv(conf->session.ttl.udp);
		printf(",");
		print_time_csv(conf->session.ttl.tcp_est);
		printf(",");
		print_time_csv(conf->session.ttl.tcp_trans);
		printf(",");
		print_time_csv(conf->session.ttl.icmp);
		printf(",");
		print_time_csv(conf->global.nat64.ttl.frag);
		printf(",");

		print_bool(conf->session.joold.enabled);
		printf(",");
		printf("%u", conf->session.joold.queue_capacity);
		printf(",");
		printf("%u", conf->session.joold.timer_period);
	}
	printf("\n");

	return 0;
}

int global_display(bool csv)
{
	struct request_hdr request;
	jool_response_cb cb;

	init_request_hdr(&request, sizeof(request), MODE_GLOBAL, OP_DISPLAY);
	cb = csv ? handle_display_response_csv : handle_display_response;

	return netlink_request(&request, request.length, cb, NULL);
}

int global_update(__u8 type, size_t size, void *data)
{
	struct request_hdr *hdr;
	void *payload;
	size_t len;
	int result;

	len = sizeof(*hdr) + sizeof(type) + size;
	hdr = malloc(len);
	if (!hdr)
		return -ENOMEM;
	payload = hdr + 1;

	init_request_hdr(hdr, len, MODE_GLOBAL, OP_UPDATE);
	memcpy(payload, &type, sizeof(type));
	memcpy(payload + sizeof(type), data, size);

	result = netlink_request(hdr, len, NULL, NULL);
	free(hdr);
	return result;
}
