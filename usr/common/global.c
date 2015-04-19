#include "nat64/usr/global.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/types.h"
#include "nat64/usr/netlink.h"
#include <errno.h>


static int handle_display_response(struct nl_msg *msg, void *arg)
{
	struct global_config *conf = nlmsg_data(nlmsg_hdr(msg));
	__u16 *plateaus;
	int i;

	printf("\n");
	printf("  Status: %s\n", conf->jool_status ? "Enabled" : "Disabled");
	printf("  Manually disabled (--%s, --%s): %s\n", OPTNAME_ENABLE, OPTNAME_DISABLE,
			conf->is_disable ? "ON" : "OFF");
	printf("\n");

	printf("  --%s: %s\n", OPTNAME_ZEROIZE_TC,
			conf->reset_traffic_class ? "ON" : "OFF");
	printf("  --%s: %s\n", OPTNAME_OVERRIDE_TOS,
			conf->reset_tos ? "ON" : "OFF");
	printf("  --%s: %u (0x%x)\n", OPTNAME_TOS,
			conf->new_tos, conf->new_tos);
	printf("  --%s:\n", OPTNAME_MTU_PLATEAUS);
	plateaus = (__u16 *) (conf + 1);
	for (i = 0; i < conf->mtu_plateau_count; i++) {
		printf("      %u\n", plateaus[i]);
	}

#ifdef STATEFUL
	printf("  --%s: %llu\n", OPTNAME_MAX_SO,
			conf->max_stored_pkts);
	printf("  --%s: %s\n", OPTNAME_SRC_ICMP6E_BETTER,
			conf->src_icmp6errs_better ? "ON" : "OFF");
#else
	printf("  --%s: %s\n", OPTNAME_AMEND_UDP_CSUM,
			conf->compute_udp_csum_zero ? "ON" : "OFF");
	printf("  --%s: 0x%x\n", OPTNAME_EAM_ENABLED_FIELDS,
			conf->eam_enabled_fields);
	printf("  --%s: %s\n", OPTNAME_RANDOMIZE_RFC6791,
			conf->randomize_error_addresses ? "ON" : "OFF");
#endif
	printf("\n");

	printf("  --%s: ", OPTNAME_ALLOW_ATOMIC_FRAGS);
	if (!conf->atomic_frags.df_always_on
			&& !conf->atomic_frags.build_ipv6_fh
			&& conf->atomic_frags.build_ipv4_id
			&& conf->atomic_frags.lower_mtu_fail)
		printf("OFF\n");
	else if (conf->atomic_frags.df_always_on
			&& conf->atomic_frags.build_ipv6_fh
			&& !conf->atomic_frags.build_ipv4_id
			&& !conf->atomic_frags.lower_mtu_fail)
		printf("ON\n");
	else
		printf("Mixed\n");

	printf("    --%s: %s\n", OPTNAME_DF_ALWAYS_ON,
			conf->atomic_frags.df_always_on ? "ON" : "OFF");
	printf("    --%s: %s\n", OPTNAME_GENERATE_FH,
			conf->atomic_frags.build_ipv6_fh ? "ON" : "OFF");
	printf("    --%s: %s\n", OPTNAME_GENERATE_ID4,
			conf->atomic_frags.build_ipv4_id ? "ON" : "OFF");
	printf("    --%s: %s\n", OPTNAME_FIX_ILLEGAL_MTUS,
			conf->atomic_frags.lower_mtu_fail ? "ON" : "OFF");
	printf("\n");

#ifdef STATEFUL
	printf("  Additional Logging:\n");
	printf("  --%s: %s\n", OPTNAME_BIB_LOGGING,
			conf->bib_logging ? "ON" : "OFF");
	printf("  --%s: %s\n", OPTNAME_SESSION_LOGGING,
			conf->session_logging ? "ON" : "OFF");
	printf("\n");

	printf("  Filtering:\n");
	printf("    --%s: %s\n", OPTNAME_DROP_BY_ADDR,
			conf->drop_by_addr ? "ON" : "OFF");
	printf("    --%s: %s\n", OPTNAME_DROP_ICMP6_INFO,
			conf->drop_icmp6_info ? "ON" : "OFF");
	printf("    --%s: %s\n",
			OPTNAME_DROP_EXTERNAL_TCP, conf->drop_external_tcp ? "ON" : "OFF");
	printf("\n");

	printf("  Timeouts:\n");
	printf("    --%s: ", OPTNAME_UDP_TIMEOUT);
	print_time_friendly(conf->ttl.udp);
	printf("    --%s: ", OPTNAME_TCPEST_TIMEOUT);
	print_time_friendly(conf->ttl.tcp_est);
	printf("    --%s: ", OPTNAME_TCPTRANS_TIMEOUT);
	print_time_friendly(conf->ttl.tcp_trans);
	printf("    --%s: ", OPTNAME_ICMP_TIMEOUT);
	print_time_friendly(conf->ttl.icmp);
	printf("    --%s: ", OPTNAME_FRAG_TIMEOUT);
	print_time_friendly(conf->ttl.frag);
	printf("\n");
#endif

	return 0;
}

int global_display(void)
{
	struct request_hdr request;
	init_request_hdr(&request, sizeof(request), MODE_GLOBAL, OP_DISPLAY);
	return netlink_request(&request, request.length, handle_display_response, NULL);
}

static int handle_update_response(struct nl_msg *msg, void *arg)
{
	log_info("Value changed successfully.");
	return 0;
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

	result = netlink_request(main_hdr, len, handle_update_response, NULL);
	free(main_hdr);
	return result;
}
