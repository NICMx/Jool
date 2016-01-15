#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the Packet queue module");

#include "nat64/unit/unit_test.h"
#include "nat64/mod/common/config.h"

static bool compare_global_configs(struct global_config *expected,
		struct global_config *actual)
{
	bool success = true;
	__u16 i;

	success &= ASSERT_UINT(expected->is_disable,
			actual->is_disable,
			"is_disable");
	success &= ASSERT_UINT(expected->reset_traffic_class,
			actual->reset_traffic_class,
			"reset_traffic_class");
	success &= ASSERT_UINT(expected->reset_tos,
			actual->reset_tos,
			"reset_tos");
	success &= ASSERT_UINT(expected->new_tos,
			actual->new_tos,
			"new_tos");

	success &= ASSERT_UINT(expected->atomic_frags.df_always_on,
			actual->atomic_frags.df_always_on,
			"df_always_on");
	success &= ASSERT_UINT(expected->atomic_frags.build_ipv6_fh,
			actual->atomic_frags.build_ipv6_fh,
			"build_ipv6_fh");
	success &= ASSERT_UINT(expected->atomic_frags.build_ipv4_id,
			actual->atomic_frags.build_ipv4_id,
			"build_ipv4_id");
	success &= ASSERT_UINT(expected->atomic_frags.lower_mtu_fail,
			actual->atomic_frags.lower_mtu_fail,
			"lower_mtu_fail");

	success &= ASSERT_UINT(expected->mtu_plateau_count,
			actual->mtu_plateau_count,
			"mtu_plateau_count");
	if (success) {
		for (i = 0; i < expected->mtu_plateau_count; i++) {
			success &= ASSERT_UINT(expected->mtu_plateaus[i],
					actual->mtu_plateaus[i],
					"mtu_plateaus");
		}
	}

	success &= ASSERT_U64(expected->nat64.ttl.frag,
			actual->nat64.ttl.frag,
			"ttl.frag");

	success &= ASSERT_UINT(expected->nat64.drop_by_addr,
			actual->nat64.drop_by_addr,
			"drop_by_addr equals");
	success &= ASSERT_UINT(expected->nat64.drop_external_tcp,
			actual->nat64.drop_external_tcp,
			"drop_external_tcp equals");
	success &= ASSERT_UINT(expected->nat64.drop_icmp6_info,
			actual->nat64.drop_icmp6_info,
			"drop_icmp6_info equals");

	return success;
}

/**
 * tests
 */

/** 
 * Get the config from the jool kernel app, then serialized a local config copy, 
 * then deserialize the buffer and finally compare the configs. 
 * */
static bool basic_test(void)
{
	unsigned char *buffer;
	size_t buffer_len;
	bool success = true;
	struct global_configuration *config;
	struct global_config clone;

	if (config_init(&config, false))
		return false;

	if (serialize_global_config(&config->cfg, true, &buffer, &buffer_len))
		return false;
	if (deserialize_global_config(buffer, buffer_len, &clone))
		return false;

	success &= compare_global_configs(&config->cfg, &clone);
	kfree(buffer);
	config_put(config);
	kfree(clone.mtu_plateaus);
	return success;
}

/**
 * Same as above, the only difference is that we set NULL the mtu_plateaus from
 * the local translate config.
 */
static bool translate_nulls_mtu(void)
{
	unsigned char *buffer;
	size_t buffer_len;
	bool success = true;
	struct global_configuration *config;
	struct global_config clone;

	if (config_init(&config, false))
		return false;

	/*
	 * lets modify our local config manually, jool's update functions wont
	 * update to null
	 */
	kfree(config->cfg.mtu_plateaus);
	config->cfg.mtu_plateaus = NULL;
	config->cfg.mtu_plateau_count = 0;

	if (serialize_global_config(&config->cfg, true, &buffer, &buffer_len))
		return false;
	if (deserialize_global_config(buffer, buffer_len, &clone))
		return false;

	success &= compare_global_configs(&config->cfg, &clone);

	/* the "compare_global_configs" will not evaluate the mtu_plateaus
	 * because of the plateau_count = 0
	 */
	success &= ASSERT_PTR(NULL, config->cfg.mtu_plateaus,
			"local config mtu_plateaus");
	success &= ASSERT_PTR(NULL, clone.mtu_plateaus,
			"deserialized config mtu_plateaus");

	kfree(buffer);
	config_put(config);
	kfree(clone.mtu_plateaus);
	return success;
}

static int configproto_test_init(void)
{
	START_TESTS("Packet queue");

	CALL_TEST(basic_test(), "basic test");
	CALL_TEST(translate_nulls_mtu(), "nulls mtus");

	END_TESTS;
}

static void configproto_test_exit(void)
{
	/* No code. */
}

module_init(configproto_test_init);
module_exit(configproto_test_exit);
