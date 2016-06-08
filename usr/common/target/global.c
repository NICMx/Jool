#include "nat64/usr/global.h"

#include <errno.h>
#include "nat64/common/types.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/netlink.h"


static char *print_status(struct global_config *conf)
{
	return conf->status ? "Enabled" : "Disabled";
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

static void print_rfc6791v6_prefix(struct full_config *config) {

	char buffer[INET6_ADDRSTRLEN];

	if (config->global.siit.use_rfc6791_v6) {

		inet_ntop(AF_INET6, &config->global.siit.rfc6791_v6_prefix, buffer, INET6_ADDRSTRLEN);
		printf("  --%s: %s/%u\n", OPTNAME_RFC6791V6_PREFIX, buffer, config->global.siit.rfc6791_v6_prefix.len);

	} else {
		printf("  --%s: %s\n", OPTNAME_RFC6791V6_PREFIX,"(not set)");
	}

}


static void print_csv_rfc6791v6_prefix(struct full_config *config) {

	char buffer[INET6_ADDRSTRLEN];

	if (config->global.siit.use_rfc6791_v6) {

		inet_ntop(AF_INET6, &config->global.siit.rfc6791_v6_prefix, buffer, INET6_ADDRSTRLEN);
		printf("  --%s: %s/%u\n", OPTNAME_RFC6791V6_PREFIX, buffer, config->global.siit.rfc6791_v6_prefix.len);

	} else {
		printf("  --%s: %s\n", OPTNAME_RFC6791V6_PREFIX,"(not set)");
	}

}


static int handle_display_response(struct jool_response *response, void *arg)
{
	struct full_config *conf = response->payload;

	if (response->payload_len != sizeof(struct full_config)) {
		log_err("Jool's response has a bogus length. (expected %zu, got %zu)",
				sizeof(struct full_config),
				response->payload_len);
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

		printf("  --%s: %u (0b", OPTNAME_F_ARGS, conf->global.nat64.f_args);
		print_binary(conf->global.nat64.f_args, 4);
		printf(")\n");
		printf("    Src addr: %s\n", print_bool(conf->global.nat64.f_args & F_ARGS_SRC_ADDR));
		printf("    Src port: %s\n", print_bool(conf->global.nat64.f_args & F_ARGS_SRC_PORT));
		printf("    Dst addr: %s\n", print_bool(conf->global.nat64.f_args & F_ARGS_DST_ADDR));
		printf("    Dst port: %s\n", print_bool(conf->global.nat64.f_args & F_ARGS_DST_PORT));

	} else {

		printf("  --%s: %s\n", OPTNAME_AMEND_UDP_CSUM,
				print_bool(conf->global.siit.compute_udp_csum_zero));
		printf("  --%s: %u (%s)\n", OPTNAME_EAM_HAIRPIN_MODE,
				conf->global.siit.eam_hairpin_mode,
				int_to_hairpin_mode(conf->global.siit.eam_hairpin_mode));
		printf("  --%s: %s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_bool(conf->global.siit.randomize_error_addresses));


		print_rfc6791v6_prefix(conf);

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
		printf("    --%s: %s\n", OPTNAME_BIB_LOGGING,
				print_bool(conf->bib.log_changes));
		printf("    --%s: %s\n", OPTNAME_SESSION_LOGGING,
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
		print_time_friendly(conf->frag.ttl);
		printf("\n");

		printf("  Synchronization:\n");
		printf("    Enabled (--%s, --%s): %s\n",
				OPTNAME_SYNCH_ENABLE , OPTNAME_SYNCH_DISABLE,
				conf->joold.enabled ? "Enabled" : "Disabled");
		printf("    --%s: %s\n", OPTNAME_SYNCH_FLUSH_ASAP, print_bool(conf->joold.flush_asap));
		printf("    --%s: ", OPTNAME_SYNCH_FLUSH_DEADLINE);
		print_time_friendly(conf->joold.flush_deadline);
		printf("    --%s: %u\n", OPTNAME_SYNCH_CAPACITY, conf->joold.capacity);
		printf("    --%s: %u\n", OPTNAME_SYNCH_MAX_PAYLOAD, conf->joold.max_payload);
	}

	return 0;
}

static int handle_display_response_csv(struct jool_response *response, void *arg)
{
	struct full_config *conf = response->payload;
	struct global_config *global = &conf->global;

	if (response->payload_len != sizeof(struct full_config)) {
		log_err("Jool's response has a bogus length. (expected %zu, got %zu)",
				sizeof(struct full_config),
				response->payload_len);
		return -EINVAL;
	}

	printf("Status,%s\n", print_status(global));
	printf("Manually enabled,%s\n", print_csv_bool(global->enabled));

	printf("%s,%s\n", OPTNAME_ZEROIZE_TC,
			print_csv_bool(global->reset_traffic_class));
	printf("%s,%s\n", OPTNAME_OVERRIDE_TOS,
			print_csv_bool(global->reset_tos));
	printf("%s,%u\n", OPTNAME_TOS, global->new_tos);

	printf("%s,%s\n", OPTNAME_ALLOW_ATOMIC_FRAGS,
			print_allow_atomic_frags(global));
	printf("%s,%s\n", OPTNAME_DF_ALWAYS_ON,
			print_csv_bool(global->atomic_frags.df_always_on));
	printf("%s,%s\n", OPTNAME_GENERATE_FH,
			print_csv_bool(global->atomic_frags.build_ipv6_fh));
	printf("%s,%s\n", OPTNAME_GENERATE_ID4,
			print_csv_bool(global->atomic_frags.build_ipv4_id));
	printf("%s,%s\n", OPTNAME_FIX_ILLEGAL_MTUS,
			print_csv_bool(global->atomic_frags.lower_mtu_fail));

	printf("%s,", OPTNAME_MTU_PLATEAUS);
	printf("\"");
	print_plateaus(global, ",");
	printf("\"\n");

	if (xlat_is_siit()) {
		printf("%s,%s\n", OPTNAME_AMEND_UDP_CSUM,
				print_csv_bool(global->siit.compute_udp_csum_zero));
		printf("%s,%s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_csv_bool(global->siit.randomize_error_addresses));
		printf("%s,%s\n", OPTNAME_EAM_HAIRPIN_MODE,
				int_to_hairpin_mode(global->siit.eam_hairpin_mode));

		print_csv_rfc6791v6_prefix(conf);

	} else {
		printf("%s,%s\n", OPTNAME_DROP_BY_ADDR,
				print_csv_bool(global->nat64.drop_by_addr));
		printf("%s,%s\n", OPTNAME_DROP_ICMP6_INFO,
				print_csv_bool(global->nat64.drop_icmp6_info));
		printf("%s,%s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_csv_bool(global->nat64.drop_external_tcp));
		printf("%s,%s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_csv_bool(global->nat64.src_icmp6errs_better));
		printf("%s,%u\n", OPTNAME_F_ARGS,
				global->nat64.f_args);
		printf("%s,%s\n", OPTNAME_BIB_LOGGING,
				print_csv_bool(conf->bib.log_changes));
		printf("%s,%s\n", OPTNAME_SESSION_LOGGING,
				print_csv_bool(conf->session.log_changes));

		printf("%s,%u\n", OPTNAME_MAX_SO,
				conf->session.pktqueue.max_stored_pkts);

		printf("joold Enabled,%s\n",
				print_csv_bool(conf->joold.enabled));
		printf("%s,%s\n", OPTNAME_SYNCH_FLUSH_ASAP,
				print_csv_bool(conf->joold.flush_asap));
		printf("%s,", OPTNAME_SYNCH_FLUSH_DEADLINE);
		print_time_csv(conf->joold.flush_deadline);
		printf("\n%s,%u\n", OPTNAME_SYNCH_CAPACITY,
				conf->joold.capacity);
		printf("%s,%u\n", OPTNAME_SYNCH_MAX_PAYLOAD,
				conf->joold.max_payload);

		printf("%s,", OPTNAME_UDP_TIMEOUT);
		print_time_csv(conf->session.ttl.udp);
		printf("\n%s,", OPTNAME_TCPEST_TIMEOUT);
		print_time_csv(conf->session.ttl.tcp_est);
		printf("\n%s,", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_csv(conf->session.ttl.tcp_trans);
		printf("\n%s,", OPTNAME_ICMP_TIMEOUT);
		print_time_csv(conf->session.ttl.icmp);
		printf("\n%s,", OPTNAME_FRAG_TIMEOUT);
		print_time_csv(conf->frag.ttl);
		printf("\n");
	}

	return 0;
}

int global_display(bool csv)
{
	struct request_hdr request;
	jool_response_cb cb;

	init_request_hdr(&request, MODE_GLOBAL, OP_DISPLAY);
	cb = csv ? handle_display_response_csv : handle_display_response;

	return netlink_request(&request, sizeof(request), cb, NULL);
}

int global_update(__u16 type, size_t size, void *data)
{
	struct request_hdr *hdr;
	struct global_value *chunk;
	void *payload;
	size_t len;
	int result;

	len = sizeof(struct request_hdr) + sizeof(struct global_value) + size;
	hdr = malloc(len);
	if (!hdr)
		return -ENOMEM;
	chunk = (struct global_value *)(hdr + 1);
	payload = chunk + 1;

	init_request_hdr(hdr, MODE_GLOBAL, OP_UPDATE);
	chunk->type = type;
	chunk->len = sizeof(struct global_value) + size;
	memcpy(payload, data, size);

	result = netlink_request(hdr, len, NULL, NULL);
	free(hdr);
	return result;
}
