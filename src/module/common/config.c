#include "config.h"

#include "constants.h"
#include "wkmalloc.h"

struct global_config *config_init(void)
{
	struct global_config *result;
	struct global_config_usr *config;
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	result = wkmalloc(struct global_config, GFP_KERNEL);
	if (!result)
		return NULL;
	kref_init(&result->refcounter);
	config = &result->cfg;

	config->xlator_type = DEFAULT_XLATOR_TYPE;
	config->status = 0; /* This is never read, but whatever. */
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	memcpy(config->mtu_plateaus, &plateaus, sizeof(plateaus));
	config->mtu_plateau_count = ARRAY_SIZE(plateaus);

	config->compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
	config->randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
	config->eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
	config->use_rfc6791_v6 = false;
	memset(&config->rfc6791_prefix6, 0, sizeof(config->rfc6791_prefix6));
	config->use_rfc6791_v4 = false;
	memset(&config->rfc6791_prefix4, 0, sizeof(config->rfc6791_prefix4));

	config->drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
	config->src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
	config->f_args = DEFAULT_F_ARGS;
	config->handle_rst_during_fin_rcv = DEFAULT_HANDLE_FIN_RCV_RST;

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

void config_copy(struct global_config_usr *from, struct global_config_usr *to)
{
	memcpy(to, from, sizeof(*from));
}

void prepare_config_for_userspace(struct full_config *config, bool pools_empty)
{
	struct bib_config *bib;
	struct fragdb_config *frag;
	struct joold_config *joold;

	config->global.status = !pools_empty;

	bib = &config->bib;
	bib->ttl.tcp_est = jiffies_to_msecs(bib->ttl.tcp_est);
	bib->ttl.tcp_trans = jiffies_to_msecs(bib->ttl.tcp_trans);
	bib->ttl.udp = jiffies_to_msecs(bib->ttl.udp);
	bib->ttl.icmp = jiffies_to_msecs(bib->ttl.icmp);

	frag = &config->frag;
	frag->ttl = jiffies_to_msecs(frag->ttl);

	joold = &config->joold;
	joold->flush_deadline = jiffies_to_msecs(joold->flush_deadline);
}
