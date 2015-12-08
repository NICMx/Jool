#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include "nat64/common/config.h"
#include "nat64/common/types.h"

int config_init(bool is_disable);
void config_destroy(void);

int config_clone(struct global_config *clone);
void config_replace(struct global_config *new);

unsigned long config_get_ttl_udp(void);
unsigned long config_get_ttl_tcpest(void);
unsigned long config_get_ttl_tcptrans(void);
unsigned long config_get_ttl_icmp(void);

unsigned int config_get_max_pkts(void);
bool config_get_src_icmp6errs_better(void);
unsigned int config_get_f_args(void);

bool config_get_bib_logging(void);
bool config_get_session_logging(void);

bool config_get_filter_icmpv6_info(void);
bool config_get_addr_dependent_filtering(void);
bool config_get_drop_external_connections(void);

bool config_amend_zero_csum(void);
enum eam_hairpinning_mode config_eam_hairpin_mode(void);
bool config_randomize_rfc6791_pool(void);

bool config_get_reset_traffic_class(void);
void config_get_hdr4_config(bool *reset_tos, __u8 *new_tos, bool *build_ipv4_id,
		bool *df_always_on);
bool config_get_build_ipv6_fh(void);
bool config_get_lower_mtu_fail(void);
void config_get_mtu_plateaus(__u16 **plateaus, __u16 *count);
bool config_is_xlat_disabled(void);

unsigned long config_get_ttl_frag(void);

#endif /* _JOOL_MOD_CONFIG_H */
