#include <linux/slab.h>
#include <linux/inet.h>

#include "nf_nat64_types.h"
#include "nf_nat64_config.h"


struct configuration config;
const __u16 DEFAULT_MTU_PLATEAUS[] = { 65535, 32000, 17914, 8166,
		4352, 2002, 1492, 1006,
		508, 296, 68 };

bool nat64_load_default_config(void)
{
	// TODO (later) que el módulo no haga nada mientras esto no está overrideado.
	config.ipv4_pool_range_first.s_addr = in_aton("12.12.12.12");
	config.ipv4_pool_range_last.s_addr = in_aton("12.12.12.14");

	config.packet_head_room = 0;
	config.packet_tail_room = 32;
	config.override_ipv6_traffic_class = false;
	config.override_ipv4_traffic_class = false;
	config.ipv4_traffic_class = 0;
	config.df_always_set = true;
	config.generate_ipv4_id = false;
	config.improve_mtu_failure_rate = true;
	config.ipv6_nexthop_mtu = 1280;
	config.ipv4_nexthop_mtu = 576;

	config.mtu_plateau_count = ARRAY_SIZE(DEFAULT_MTU_PLATEAUS);
	config.mtu_plateaus = kmalloc(sizeof(DEFAULT_MTU_PLATEAUS), GFP_ATOMIC);
	if (!config.mtu_plateaus) {
		log_warning("Could not allocate memory to store the MTU plateaus.");
		return false;
	}
	memcpy(config.mtu_plateaus, &DEFAULT_MTU_PLATEAUS, sizeof(DEFAULT_MTU_PLATEAUS));

	return true;
}
