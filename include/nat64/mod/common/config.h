#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"

/*
 * TODO maybe this should be called "global_config" and "global_config" should
 * be called "global_config_usr".
 */
struct global_configuration {
	/* TODO rename as "values" or something */
	struct global_config config;
	struct kref refcounter;
};

int config_init(struct global_configuration **global, bool disable);
void config_get(struct global_configuration *global);
void config_put(struct global_configuration *global);

//int config_clone(struct global_config *clone);
//void config_replace(struct global_config *new);

/* TODO there's probably not much point to keeping these functions around. */

unsigned long config_get_ttl_udp(struct global_configuration *config);
unsigned long config_get_ttl_tcpest(struct global_configuration *config);
unsigned long config_get_ttl_tcptrans(struct global_configuration *config);
unsigned long config_get_ttl_icmp(struct global_configuration *config);

unsigned int config_get_max_pkts(struct global_configuration *config);
bool config_get_src_icmp6errs_better(struct global_configuration *config);
bool config_get_bib_logging(struct global_configuration *config);
bool config_get_session_logging(struct global_configuration *config);

bool config_get_filter_icmpv6_info(struct global_configuration *config);
bool config_get_addr_dependent_filtering(struct global_configuration *config);
bool config_get_drop_external_connections(struct global_configuration *config);

bool config_amend_zero_csum(struct global_configuration *config);
enum eam_hairpinning_mode config_eam_hairpin_mode(struct global_configuration *config);
bool config_randomize_rfc6791_pool(struct global_configuration *config);

bool config_get_reset_traffic_class(struct global_configuration *config);
void config_get_hdr4_config(struct global_configuration *config,
		bool *reset_tos, __u8 *new_tos, bool *build_ipv4_id,
		bool *df_always_on);
bool config_get_build_ipv6_fh(struct global_configuration *config);
bool config_get_lower_mtu_fail(struct global_configuration *config);
void config_get_mtu_plateaus(struct global_configuration *config,
		__u16 **plateaus, __u16 *count);
bool config_is_xlat_disabled(struct global_configuration *config);

unsigned long config_get_ttl_frag(struct global_configuration *config);

#endif /* _JOOL_MOD_CONFIG_H */
