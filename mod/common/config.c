#include "nat64/mod/common/config.h"

#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/wkmalloc.h"

static DEFINE_MUTEX(lock);

RCUTAG_USR
int config_init(struct global_config **result)
{
	struct global_config_usr *config;
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	*result = wkmalloc(struct global_config, GFP_KERNEL);
	if (!(*result))
		return -ENOMEM;
	kref_init(&(*result)->refcounter);
	config = &(*result)->cfg;

	config->status = 0; /* This is never read, but whatever. */
	config->enabled = DEFAULT_INSTANCE_ENABLED;
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;

	if (xlat_is_siit()) {
		config->siit.compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
		config->siit.eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
		config->siit.randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
		config->siit.use_rfc6791_v6 = DEFAULT_USE_RFC6791V6_PREFIX;
	} else {
		config->nat64.src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
		config->nat64.drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
		config->nat64.f_args = DEFAULT_F_ARGS;
		config->nat64.handle_rst_during_fin_rcv = DEFAULT_HANDLE_FIN_RCV_RST;
	}

	config->mtu_plateau_count = ARRAY_SIZE(plateaus);
	memcpy(config->mtu_plateaus, &plateaus, sizeof(plateaus));

	return 0;
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

RCUTAG_PKT
void config_copy(struct global_config_usr *from, struct global_config_usr *to)
{
	memcpy(to, from, sizeof(*from));
}

RCUTAG_FREE
void prepare_config_for_userspace(struct full_config *config, bool pools_empty)
{
	struct global_config_usr *global;
	struct bib_config *bib;
	struct fragdb_config *frag;
	struct joold_config *joold;

	global = &config->global;
	global->status = global->enabled && !pools_empty;

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
