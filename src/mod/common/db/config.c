#include "mod/common/db/config.h"

#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "common/constants.h"
#include "common/globals.h"
#include "mod/common/log.h"

int globals_init(struct globals *config, xlator_type type,
		struct config_prefix6 *pool6)
{
	static const __u16 PLATEAUS[] = DEFAULT_MTU_PLATEAUS;
	int error;

	if (pool6) {
		/* TODO (fine) force */
		error = validate_pool6(NULL, pool6, true);
		if (error)
			return error;
	}

	config->status = 0; /* This is never read, but whatever. */
	config->enabled = DEFAULT_INSTANCE_ENABLED;
	config->trace = false;
	if (pool6)
		config->pool6 = *pool6;
	else
		config->pool6.set = false;
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	memcpy(config->plateaus.values, &PLATEAUS, sizeof(PLATEAUS));
	config->plateaus.count = ARRAY_SIZE(PLATEAUS);

	switch (type) {
	case XT_SIIT:
		config->siit.compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
		config->siit.eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
		config->siit.randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
		config->siit.rfc6791_prefix6.set = false;
		config->siit.rfc6791_prefix4.set = false;
		break;

	case XT_NAT64:
		config->nat64.drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
		config->nat64.src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
		config->nat64.f_args = DEFAULT_F_ARGS;
		config->nat64.handle_rst_during_fin_rcv = DEFAULT_HANDLE_FIN_RCV_RST;

		config->nat64.bib.ttl.tcp_est = 1000 * TCP_EST;
		config->nat64.bib.ttl.tcp_trans = 1000 * TCP_TRANS;
		config->nat64.bib.ttl.udp = 1000 * UDP_DEFAULT;
		config->nat64.bib.ttl.icmp = 1000 * ICMP_DEFAULT;
		config->nat64.bib.bib_logging = DEFAULT_BIB_LOGGING;
		config->nat64.bib.session_logging = DEFAULT_SESSION_LOGGING;
		config->nat64.bib.drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
		config->nat64.bib.drop_external_tcp = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
		config->nat64.bib.max_stored_pkts = DEFAULT_MAX_STORED_PKTS;

		config->nat64.joold.enabled = DEFAULT_JOOLD_ENABLED;
		config->nat64.joold.flush_asap = DEFAULT_JOOLD_FLUSH_ASAP;
		config->nat64.joold.flush_deadline = 1000 * DEFAULT_JOOLD_DEADLINE;
		config->nat64.joold.capacity = DEFAULT_JOOLD_CAPACITY;
		config->nat64.joold.max_payload = DEFAULT_JOOLD_MAX_PAYLOAD;
		break;

	default:
		log_err("Unknown translator type: %d", type);
		return -EINVAL;
	}

	return 0;
}

void prepare_config_for_userspace(struct globals *config, bool pools_empty)
{
	config->status = config->enabled && !pools_empty;
}
