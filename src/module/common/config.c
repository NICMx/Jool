#include "config.h"

#include "constants.h"
#include "wkmalloc.h"

struct global_config *config_init(xlator_type type)
{
	struct global_config *result;
	struct globals *config;
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	result = wkmalloc(struct global_config, GFP_KERNEL);
	if (!result)
		return NULL;
	kref_init(&result->refcounter);
	config = &result->cfg;

	config->xlator_type = type;
	memset(&config->pool6, 0, sizeof(config->pool6));
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	memset(config->mtu_plateaus, 0, sizeof(config->mtu_plateaus));
	memcpy(config->mtu_plateaus, &plateaus, sizeof(plateaus));

	config->compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
	config->randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
	config->eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
	memset(&config->rfc6791_prefix6, 0, sizeof(config->rfc6791_prefix6));
	memset(&config->rfc6791_prefix4, 0, sizeof(config->rfc6791_prefix4));

	config->drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
	config->src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
	config->f_args = DEFAULT_F_ARGS;
	config->handle_rst_during_fin_rcv = DEFAULT_HANDLE_FIN_RCV_RST;

	/* TODO testing defaults. Remove. */
	config->xlator_type = XLATOR_NAT64;
	config->pool6.addr.s6_addr[1] = 0x64;
	config->pool6.addr.s6_addr[2] = 0xff;
	config->pool6.addr.s6_addr[3] = 0x9b;
	config->pool6.len = 96;

	return result;
}

void config_get(struct global_config *config)
{
	kref_get(&config->refcounter);
}

static void destroy_config(struct kref *refcounter)
{
	struct global_config *config;
	config = container_of(refcounter, struct global_config, refcounter);
	wkfree(struct global_config, config);
}

void config_put(struct global_config *config)
{
	kref_put(&config->refcounter, destroy_config);
}

void prepare_config_for_userspace(struct globals *cfg)
{
	cfg->bib.ttl.tcp_est = jiffies_to_msecs(cfg->bib.ttl.tcp_est);
	cfg->bib.ttl.tcp_trans = jiffies_to_msecs(cfg->bib.ttl.tcp_trans);
	cfg->bib.ttl.udp = jiffies_to_msecs(cfg->bib.ttl.udp);
	cfg->bib.ttl.icmp = jiffies_to_msecs(cfg->bib.ttl.icmp);
	cfg->frag.ttl = jiffies_to_msecs(cfg->frag.ttl);
	cfg->joold.flush_deadline = jiffies_to_msecs(cfg->joold.flush_deadline);
}
