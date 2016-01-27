#include "nat64/mod/common/config.h"

#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/types.h"

static DEFINE_MUTEX(lock);

RCUTAG_USR
int config_init(struct global_configuration **result, bool disable)
{
	struct global_config *config;
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	*result = kmalloc(sizeof(**result), GFP_KERNEL);
	if (!(*result))
		return -ENOMEM;
	kref_init(&(*result)->refcounter);
	config = &(*result)->cfg;

	config->jool_status = 0; /* This is never read, but whatever. */
	config->is_disable = (__u8)disable;
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;
	config->synch_elements_limit = DEFAULT_SYNCH_ELEMENTS_LIMIT;
	config->synch_elements_period = DEFAULT_SYNCH_ELEMENTS_PERIOD;
	config->synch_elements_threshold = DEFAULT_SYNCH_ELEMENTS_THRESHOLD;
	config->synch_enabled = 0;

	config->atomic_frags.df_always_on = DEFAULT_DF_ALWAYS_ON;
	config->atomic_frags.build_ipv6_fh = DEFAULT_BUILD_IPV6_FH;
	config->atomic_frags.build_ipv4_id = DEFAULT_BUILD_IPV4_ID;
	config->atomic_frags.lower_mtu_fail = DEFAULT_LOWER_MTU_FAIL;

	config->nat64.ttl.frag = msecs_to_jiffies(1000 * FRAGMENT_MIN);
	config->nat64.src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
	config->nat64.drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
	config->nat64.drop_external_tcp = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
	config->nat64.drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;

	config->siit.compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
	config->siit.eam_hairpin_mode = DEFAULT_EAM_HAIRPIN_MODE;
	config->siit.randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;

	config->mtu_plateau_count = ARRAY_SIZE(plateaus);
	config->mtu_plateaus = kmalloc(sizeof(plateaus), GFP_ATOMIC);
	if (!config->mtu_plateaus) {
		log_err("Could not allocate memory to store the MTU plateaus.");
		kfree(*result);
		return -ENOMEM;
	}
	memcpy(config->mtu_plateaus, &plateaus, sizeof(plateaus));

	return 0;
}

void config_get(struct global_configuration *config)
{
	kref_get(&config->refcounter);
}

static void destroy_config(struct kref *refcounter)
{
	struct global_configuration *config;
	config = container_of(refcounter, typeof(*config), refcounter);
	kfree(config->cfg.mtu_plateaus);
	kfree(config);
}

void config_put(struct global_configuration *config)
{
	kref_put(&config->refcounter, destroy_config);
}

RCUTAG_PKT
int config_clone(struct global_configuration *from, struct global_configuration **to)
{
	struct global_configuration *result;
	size_t len;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;
	kref_init(&result->refcounter);

	memcpy(result, from, sizeof(*from));

	len = sizeof(*from->cfg.mtu_plateaus) * from->cfg.mtu_plateau_count;
	result->cfg.mtu_plateaus = kmalloc(len, GFP_ATOMIC);
	if (!result->cfg.mtu_plateaus) {
		config_put(result);
		return -ENOMEM;
	}
	memcpy(result->cfg.mtu_plateaus, from->cfg.mtu_plateaus, len);

	*to = result;
	return 0;
}

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to _FREE. */
int serialize_global_config(struct global_config *config, bool pools_empty,
		unsigned char **buffer_out, size_t *buffer_len_out)
{
	unsigned char *buffer;
	struct global_config *tmp;
	size_t mtus_len;
	bool disabled;

	mtus_len = config->mtu_plateau_count * sizeof(*config->mtu_plateaus);

	buffer = kmalloc(sizeof(*config) + mtus_len, GFP_KERNEL);
	if (!buffer) {
		log_debug("Could not allocate the configuration structure.");
		return -ENOMEM;
	}

	memcpy(buffer, config, sizeof(*config));
	memcpy(buffer + sizeof(*config), config->mtu_plateaus, mtus_len);
	tmp = (struct global_config *) buffer;

	tmp->nat64.ttl.frag = jiffies_to_msecs(config->nat64.ttl.frag);

	disabled = config->is_disable || pools_empty;
	tmp->jool_status = !disabled;

	*buffer_out = buffer;
	*buffer_len_out = sizeof(*config) + mtus_len;
	return 0;
}

/* TODO (issue164) this is not being used anywhere. Review after merging #164. */
int deserialize_global_config(void *buffer, __u16 buffer_len, struct global_config *target_out)
{
	size_t mtus_len;

	memcpy(target_out, buffer, sizeof(*target_out));

	target_out->mtu_plateaus = NULL;
	if (target_out->mtu_plateau_count) {
		mtus_len = target_out->mtu_plateau_count * sizeof(*target_out->mtu_plateaus);
		target_out->mtu_plateaus = kmalloc(mtus_len, GFP_ATOMIC);
		if (!target_out->mtu_plateaus) {
			log_debug("Could not allocate the config's plateaus.");
			return -ENOMEM;
		}
		memcpy(target_out->mtu_plateaus, buffer + sizeof(*target_out), mtus_len);
	}

	target_out->nat64.ttl.frag = msecs_to_jiffies(target_out->nat64.ttl.frag);

	return 0;
}
