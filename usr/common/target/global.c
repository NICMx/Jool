#include "nat64/usr/global.h"

#include <errno.h>
#include "nat64/common/types.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/netlink.h"


static char *print_status(struct global_config_usr *conf)
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

static void print_plateaus(struct global_config_usr *conf, char *separator)
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

static void print_rfc6791v6_prefix(struct full_config *config, bool csv)
{
	struct ipv6_prefix *prefix;
	const char *str;
	char buffer[INET6_ADDRSTRLEN];

	if (config->global.siit.use_rfc6791_v6) {
		prefix = &config->global.siit.rfc6791_v6_prefix;
		str = inet_ntop(AF_INET6, &prefix->address, buffer,
				sizeof(buffer));
		if (str)
			printf("%s/%u", str, prefix->len);
		else
			perror("inet_ntop");

	} else {
		if (!csv)
			printf("(not set)");
	}

	printf("\n");
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
	printf("  --%s: ", OPTNAME_MTU_PLATEAUS);
	print_plateaus(&conf->global, ",");
	printf("\n");

	if (xlat_is_nat64()) {

		printf("  --%s: %u\n", OPTNAME_MAX_SO,
				conf->bib.max_stored_pkts);
		printf("  --%s: %s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_bool(conf->global.nat64.src_icmp6errs_better));
		printf("  --%s: %s\n", OPTNAME_HANDLE_FIN_RCV_RST,
				print_bool(conf->global.nat64.handle_rst_during_fin_rcv));

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
		printf("  --%s: ", OPTNAME_RFC6791V6_PREFIX);
		print_rfc6791v6_prefix(conf, false);

	}
	printf("\n");

	if (xlat_is_nat64()) {
		printf("  Additional Logging:\n");
		printf("    --%s: %s\n", OPTNAME_BIB_LOGGING,
				print_bool(conf->bib.bib_logging));
		printf("    --%s: %s\n", OPTNAME_SESSION_LOGGING,
				print_bool(conf->bib.session_logging));
		printf("\n");

		printf("  Filtering:\n");
		printf("    --%s: %s\n", OPTNAME_DROP_BY_ADDR,
				print_bool(conf->bib.drop_by_addr));
		printf("    --%s: %s\n", OPTNAME_DROP_ICMP6_INFO,
				print_bool(conf->global.nat64.drop_icmp6_info));
		printf("    --%s: %s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_bool(conf->bib.drop_external_tcp));
		printf("\n");

		printf("  Timeouts:\n");
		printf("    --%s: ", OPTNAME_UDP_TIMEOUT);
		print_time_friendly(conf->bib.ttl.udp);
		printf("    --%s: ", OPTNAME_TCPEST_TIMEOUT);
		print_time_friendly(conf->bib.ttl.tcp_est);
		printf("    --%s: ", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_friendly(conf->bib.ttl.tcp_trans);
		printf("    --%s: ", OPTNAME_ICMP_TIMEOUT);
		print_time_friendly(conf->bib.ttl.icmp);
		printf("    --%s: ", OPTNAME_FRAG_TIMEOUT);
		print_time_friendly(conf->frag.ttl);
		printf("\n");

		printf("  Synchronization:\n");
		printf("    --%s: %s\n", OPTNAME_SS_ENABLED, print_bool(conf->joold.enabled));
		printf("    --%s: %s\n", OPTNAME_SS_FLUSH_ASAP, print_bool(conf->joold.flush_asap));
		printf("    --%s: ", OPTNAME_SS_FLUSH_DEADLINE);
		print_time_friendly(conf->joold.flush_deadline);
		printf("    --%s: %u\n", OPTNAME_SS_CAPACITY, conf->joold.capacity);
		printf("    --%s: %u\n", OPTNAME_SS_MAX_PAYLOAD, conf->joold.max_payload);
	}

	return 0;
}

static int handle_display_response_csv(struct jool_response *response, void *arg)
{
	struct full_config *conf = response->payload;
	struct global_config_usr *global = &conf->global;

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

	printf("%s,", OPTNAME_MTU_PLATEAUS);
	printf("\"");
	print_plateaus(global, ",");
	printf("\"\n");

	if (xlat_is_siit()) {
		printf("%s,%s\n", OPTNAME_AMEND_UDP_CSUM,
				print_csv_bool(global->siit.compute_udp_csum_zero));
		printf("%s,%s\n", OPTNAME_EAM_HAIRPIN_MODE,
				int_to_hairpin_mode(global->siit.eam_hairpin_mode));
		printf("%s,%s\n", OPTNAME_RANDOMIZE_RFC6791,
				print_csv_bool(global->siit.randomize_error_addresses));
		printf("%s,", OPTNAME_RFC6791V6_PREFIX);
		print_rfc6791v6_prefix(conf, true);

	} else {
		printf("%s,%s\n", OPTNAME_DROP_BY_ADDR,
				print_csv_bool(conf->bib.drop_by_addr));
		printf("%s,%s\n", OPTNAME_DROP_ICMP6_INFO,
				print_csv_bool(global->nat64.drop_icmp6_info));
		printf("%s,%s\n", OPTNAME_DROP_EXTERNAL_TCP,
				print_csv_bool(conf->bib.drop_external_tcp));
		printf("%s,%s\n", OPTNAME_SRC_ICMP6E_BETTER,
				print_csv_bool(global->nat64.src_icmp6errs_better));
		printf("%s,%u\n", OPTNAME_HANDLE_FIN_RCV_RST,
				global->nat64.handle_rst_during_fin_rcv);
		printf("%s,%u\n", OPTNAME_F_ARGS,
				global->nat64.f_args);
		printf("%s,%s\n", OPTNAME_BIB_LOGGING,
				print_csv_bool(conf->bib.bib_logging));
		printf("%s,%s\n", OPTNAME_SESSION_LOGGING,
				print_csv_bool(conf->bib.session_logging));

		printf("%s,%u\n", OPTNAME_MAX_SO,
				conf->bib.max_stored_pkts);

		printf("joold Enabled,%s\n",
				print_csv_bool(conf->joold.enabled));
		printf("%s,%s\n", OPTNAME_SS_FLUSH_ASAP,
				print_csv_bool(conf->joold.flush_asap));
		printf("%s,", OPTNAME_SS_FLUSH_DEADLINE);
		print_time_csv(conf->joold.flush_deadline);
		printf("\n%s,%u\n", OPTNAME_SS_CAPACITY,
				conf->joold.capacity);
		printf("%s,%u\n", OPTNAME_SS_MAX_PAYLOAD,
				conf->joold.max_payload);

		printf("%s,", OPTNAME_UDP_TIMEOUT);
		print_time_csv(conf->bib.ttl.udp);
		printf("\n%s,", OPTNAME_TCPEST_TIMEOUT);
		print_time_csv(conf->bib.ttl.tcp_est);
		printf("\n%s,", OPTNAME_TCPTRANS_TIMEOUT);
		print_time_csv(conf->bib.ttl.tcp_trans);
		printf("\n%s,", OPTNAME_ICMP_TIMEOUT);
		print_time_csv(conf->bib.ttl.icmp);
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
