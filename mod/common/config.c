#include "nat64/mod/common/config.h"
#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include "nat64/common/config.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"

static struct global_config *config;

int config_init(bool is_disable)
{
	__u16 plateaus[] = DEFAULT_MTU_PLATEAUS;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	config->jool_status = 0; /* This is never read, but whatever. */
	config->is_disable = (__u8) is_disable;
	config->reset_traffic_class = DEFAULT_RESET_TRAFFIC_CLASS;
	config->reset_tos = DEFAULT_RESET_TOS;
	config->new_tos = DEFAULT_NEW_TOS;

	config->atomic_frags.df_always_on = DEFAULT_DF_ALWAYS_ON;
	config->atomic_frags.build_ipv6_fh = DEFAULT_BUILD_IPV6_FH;
	config->atomic_frags.build_ipv4_id = DEFAULT_BUILD_IPV4_ID;
	config->atomic_frags.lower_mtu_fail = DEFAULT_LOWER_MTU_FAIL;

#ifdef STATEFUL
	config->ttl.udp = msecs_to_jiffies(1000 * UDP_DEFAULT);
	config->ttl.icmp = msecs_to_jiffies(1000 * ICMP_DEFAULT);
	config->ttl.tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	config->ttl.tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);
	config->ttl.frag = msecs_to_jiffies(1000 * FRAGMENT_MIN);
	config->max_stored_pkts = DEFAULT_MAX_STORED_PKTS;
	config->src_icmp6errs_better = DEFAULT_SRC_ICMP6ERRS_BETTER;
	config->drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
	config->drop_external_tcp = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
	config->drop_icmp6_info = DEFAULT_FILTER_ICMPV6_INFO;
	config->bib_logging = DEFAULT_BIB_LOGGING;
	config->session_logging = DEFAULT_SESSION_LOGGING;
#else
	config->compute_udp_csum_zero = DEFAULT_COMPUTE_UDP_CSUM0;
	config->randomize_error_addresses = DEFAULT_RANDOMIZE_RFC6791;
#endif

	config->mtu_plateau_count = ARRAY_SIZE(plateaus);
	config->mtu_plateaus = kmalloc(sizeof(plateaus), GFP_ATOMIC);
	if (!config->mtu_plateaus) {
		log_err("Could not allocate memory to store the MTU plateaus.");
		kfree(config);
		return -ENOMEM;
	}
	memcpy(config->mtu_plateaus, &plateaus, sizeof(plateaus));

	return 0;
}

void config_destroy(void)
{
	kfree(config->mtu_plateaus);
	kfree(config);
}

int config_clone(struct global_config *clone)
{
	struct global_config *tmp;
	size_t len;
	rcu_read_lock_bh();

	/* Clone the main structure. */
	tmp = rcu_dereference_bh(config);
	*clone = *tmp;

	/* Clone plateaus. */
	len = sizeof(*tmp->mtu_plateaus) * tmp->mtu_plateau_count;
	clone->mtu_plateaus = kmalloc(len, GFP_ATOMIC);
	if (!clone->mtu_plateaus) {
		rcu_read_unlock_bh();
		return -ENOMEM;
	}
	memcpy(clone->mtu_plateaus, tmp->mtu_plateaus, len);

	rcu_read_unlock_bh();
	return 0;
}

int config_set(struct global_config *new)
{
	struct global_config *old = config;

	rcu_assign_pointer(config, new);
	synchronize_rcu_bh();

	kfree(old->mtu_plateaus);
	kfree(old);
	return 0;
}

#define RCU_THINGY(type, field) \
	({ \
		type result; \
		rcu_read_lock_bh(); \
		result = rcu_dereference_bh(config)->field; \
		rcu_read_unlock_bh(); \
		result; \
	})

#ifdef STATEFUL

unsigned long config_get_ttl_udp(void)
{
	return RCU_THINGY(unsigned long, ttl.udp);
}

unsigned long config_get_ttl_tcpest(void)
{
	return RCU_THINGY(unsigned long, ttl.tcp_est);
}

unsigned long config_get_ttl_tcptrans(void)
{
	return RCU_THINGY(unsigned long, ttl.tcp_trans);
}

unsigned long config_get_ttl_icmp(void)
{
	return RCU_THINGY(unsigned long, ttl.icmp);
}

unsigned long config_get_ttl_frag(void)
{
	return RCU_THINGY(unsigned long, ttl.frag);
}

unsigned int config_get_max_pkts(void)
{
	return RCU_THINGY(unsigned int, max_stored_pkts);
}

bool config_get_src_icmp6errs_better(void)
{
	return RCU_THINGY(bool, src_icmp6errs_better);
}

bool config_get_bib_logging(void)
{
	return RCU_THINGY(bool, bib_logging);
}

bool config_get_session_logging(void)
{
	return RCU_THINGY(bool, session_logging);
}

bool config_get_filter_icmpv6_info(void)
{
	return RCU_THINGY(bool, drop_icmp6_info);
}

bool config_get_addr_dependent_filtering(void)
{
	return RCU_THINGY(bool, drop_by_addr);
}

bool config_get_drop_external_connections(void)
{
	return RCU_THINGY(bool, drop_external_tcp);
}

#else

bool config_amend_zero_csum(void)
{
	return RCU_THINGY(bool, compute_udp_csum_zero);
}

bool config_randomize_rfc6791_pool(void)
{
	return RCU_THINGY(bool, randomize_error_addresses);
}

#endif

bool config_get_reset_traffic_class(void)
{
	return RCU_THINGY(bool, reset_traffic_class);
}

void config_get_hdr4_config(bool *reset_tos, __u8 *new_tos, bool *build_ipv4_id,
		bool *df_always_on)
{
	struct global_config *tmp;

	rcu_read_lock_bh();
	tmp = rcu_dereference_bh(config);
	*reset_tos = tmp->reset_tos;
	*new_tos = tmp->new_tos;
	*build_ipv4_id = tmp->atomic_frags.build_ipv4_id;
	*df_always_on = tmp->atomic_frags.df_always_on;
	rcu_read_unlock_bh();
}

bool config_get_build_ipv6_fh(void)
{
	return RCU_THINGY(bool, atomic_frags.build_ipv6_fh);
}

bool config_get_lower_mtu_fail(void)
{
	return RCU_THINGY(bool, atomic_frags.lower_mtu_fail);
}

/**
 * You need to call rcu_read_lock_bh() before calling this function,
 * and then rcu_read_unlock_bh() when you don't need plateaus & count anymore.
 */
void config_get_mtu_plateaus(__u16 **plateaus, __u16 *count)
{
	struct global_config *tmp;

	tmp = rcu_dereference_bh(config);
	*plateaus = tmp->mtu_plateaus;
	*count = tmp->mtu_plateau_count;
}

bool config_get_is_disable(void)
{
	return RCU_THINGY(bool, is_disable);
}

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

#ifdef STATEFUL
	tmp->ttl.udp = jiffies_to_msecs(config->ttl.udp);
	tmp->ttl.tcp_est = jiffies_to_msecs(config->ttl.tcp_est);
	tmp->ttl.tcp_trans = jiffies_to_msecs(config->ttl.tcp_trans);
	tmp->ttl.icmp = jiffies_to_msecs(config->ttl.icmp);
	tmp->ttl.frag = jiffies_to_msecs(config->ttl.frag);
#endif
	disabled = config->is_disable || pools_empty;
	tmp->jool_status = !disabled;

	*buffer_out = buffer;
	*buffer_len_out = sizeof(*config) + mtus_len;
	return 0;
}

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

#ifdef STATEFUL
	target_out->ttl.udp = msecs_to_jiffies(target_out->ttl.udp);
	target_out->ttl.tcp_est = msecs_to_jiffies(target_out->ttl.tcp_est);
	target_out->ttl.tcp_trans = msecs_to_jiffies(target_out->ttl.tcp_trans);
	target_out->ttl.icmp = msecs_to_jiffies(target_out->ttl.icmp);
	target_out->ttl.frag = msecs_to_jiffies(target_out->ttl.frag);
#endif

	return 0;
}
