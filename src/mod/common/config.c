#include "mod/common/config.h"

#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include "common/config.h"
#include "common/constants.h"
#include "common/types.h"
#include "mod/common/tags.h"
#include "mod/common/wkmalloc.h"

static DEFINE_MUTEX(lock);

RCUTAG_USR
struct global_config *config_alloc(struct config_prefix6 *pool6)
{
	struct global_config *result;
	struct globals *config;
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	result = wkmalloc(struct global_config, GFP_KERNEL);
	if (!result)
		return NULL;
	kref_init(&result->refcounter);
	config = &result->cfg;

	config->status = 0; /* This is never read, but whatever. */
	config->enabled = DEFAULT_INSTANCE_ENABLED;
	if (pool6)
		config->pool6 = *pool6;
	else
		config->pool6.set = false;
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	memcpy(config->plateaus.values, &plateaus, sizeof(plateaus));
	config->plateaus.count = ARRAY_SIZE(plateaus);

	if (xlat_is_siit()) {
		config->siit.compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
		config->siit.eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
		config->siit.randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
		config->siit.rfc6791_prefix6.set = false;
		config->siit.rfc6791_prefix4.set = false;
	} else {
		config->nat64.drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
		config->nat64.src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
		config->nat64.f_args = DEFAULT_F_ARGS;
		config->nat64.handle_rst_during_fin_rcv = DEFAULT_HANDLE_FIN_RCV_RST;

		config->nat64.bib.bib_logging = DEFAULT_BIB_LOGGING;
		config->nat64.bib.session_logging = DEFAULT_SESSION_LOGGING;
		config->nat64.bib.drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
		config->nat64.bib.drop_external_tcp = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
		config->nat64.bib.max_stored_pkts = DEFAULT_MAX_STORED_PKTS;

		config->nat64.joold.enabled = DEFAULT_JOOLD_ENABLED;
		config->nat64.joold.flush_asap = DEFAULT_JOOLD_FLUSH_ASAP;
		config->nat64.joold.flush_deadline = DEFAULT_JOOLD_DEADLINE;
		config->nat64.joold.capacity = DEFAULT_JOOLD_CAPACITY;
		config->nat64.joold.max_payload = DEFAULT_JOOLD_MAX_PAYLOAD;
	}

	return result;
}

void config_get(struct global_config *config)
{
	kref_get(&config->refcounter);
}

static void config_release(struct kref *refcounter)
{
	struct global_config *config;
	config = container_of(refcounter, struct global_config, refcounter);
	wkfree(struct global_config, config);
}

void config_put(struct global_config *config)
{
	kref_put(&config->refcounter, config_release);
}

RCUTAG_PKT
void config_copy(struct globals *from, struct globals *to)
{
	memcpy(to, from, sizeof(*from));
}

RCUTAG_FREE
void prepare_config_for_userspace(struct globals *config, bool pools_empty)
{
	struct bib_config *bib;
	struct joold_config *joold;

	config->status = config->enabled && !pools_empty;

	bib = &config->nat64.bib;
	bib->ttl.tcp_est = jiffies_to_msecs(bib->ttl.tcp_est);
	bib->ttl.tcp_trans = jiffies_to_msecs(bib->ttl.tcp_trans);
	bib->ttl.udp = jiffies_to_msecs(bib->ttl.udp);
	bib->ttl.icmp = jiffies_to_msecs(bib->ttl.icmp);

	joold = &config->nat64.joold;
	joold->flush_deadline = jiffies_to_msecs(joold->flush_deadline);
}
