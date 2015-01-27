#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/printk.h> /* pr_* */
#include <linux/ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the Packet queue module");
MODULE_ALIAS("nat64_test_pkt_queue");

#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/send_packet.h"
#include "nl_handler.c"

/* functions */
static bool compare_pktqueue_config(struct pktqueue_config *expected,
		struct pktqueue_config *actual)
{
	bool success = true;

	success &= assert_equals_u64(expected->max_pkts, actual->max_pkts,
			"pkt_queue->max_pkts equals test");

	return success;
}

static bool compare_session_config(struct sessiondb_config *expected,
		struct sessiondb_config *actual)
{
	bool success = true;

	success &= assert_equals_u64(expected->ttl.icmp, actual->ttl.icmp, "ttl.icmp equals");
	success &= assert_equals_u64(expected->ttl.tcp_est, actual->ttl.tcp_est, "ttl.tcp_est equals");
	success &= assert_equals_u64(expected->ttl.tcp_trans, actual->ttl.tcp_trans,
			"ttl.tcp_trans equals");
	success &= assert_equals_u64(expected->ttl.udp, actual->ttl.udp, "ttl.udp equals");

	return success;
}

static bool compare_filtering_config(struct filtering_config *expected,
		struct filtering_config *actual)
{
	bool success = true;

	success &= assert_equals_u8(expected->drop_by_addr, actual->drop_by_addr,
			"filtering->drop_by_addr equals");
	success &= assert_equals_u8(expected->drop_external_tcp, actual->drop_external_tcp,
			"filtering->drop_external_tcp equals");
	success &= assert_equals_u8(expected->drop_icmp6_info, actual->drop_icmp6_info,
			"filtering->drop_icmp6_info equals");

	return success;

}

static bool compare_translate_config(struct translate_config *expected,
		struct translate_config *actual)
{
	bool success = true;
	__u16 plateau;

	success &= assert_equals_u8(expected->reset_traffic_class, actual->reset_traffic_class,
			"translate: reset_traffic_class");
	success &= assert_equals_u8(expected->reset_tos, actual->reset_tos, "translate: reset_tos");
	success &= assert_equals_u8(expected->new_tos, actual->new_tos, "translate: new_tos");
	success &= assert_equals_u8(expected->df_always_on, actual->df_always_on,
			"translate: df_always_on");
	success &= assert_equals_u8(expected->build_ipv4_id, actual->build_ipv4_id,
			"translate: build_ipv4_id");
	success &= assert_equals_u8(expected->lower_mtu_fail, actual->lower_mtu_fail,
			"translate: lower_mtu_fail");
	success &= assert_equals_u16(expected->mtu_plateau_count, actual->mtu_plateau_count,
			"translate: mtu_plateau_count");
	if (success) {
		for (plateau = 0; plateau < expected->mtu_plateau_count; plateau++) {
			success &= assert_equals_u16(expected->mtu_plateaus[plateau],
					actual->mtu_plateaus[plateau], "translate: mtu_plateu");
		}
	}

	return success;
}

static bool compare_global_configs(struct global_config *expected_config,
		struct global_config *actual_config)
{
	bool success = true;

	success &= compare_pktqueue_config(&expected_config->pktqueue, &actual_config->pktqueue);
	success &= compare_session_config(&expected_config->sessiondb, &actual_config->sessiondb);
	success &= compare_filtering_config(&expected_config->filtering, &actual_config->filtering);
	success &= compare_translate_config(&expected_config->translate, &actual_config->translate);

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
	int error;
	unsigned char *buffer;
	size_t buffer_len;
	bool success = true;
	struct global_config config = { .translate.mtu_plateaus = NULL };
	struct global_config response = { .translate.mtu_plateaus = NULL };

	error = config_clone(&config);
	if (error)
		return false;

	error = serialize_global_config(&config, &buffer, &buffer_len);
	if (error)
		return false;

	error = deserialize_global_config(buffer, buffer_len, &response);
	if (error)
		return false;

	success &= compare_global_configs(&config, &response);

	kfree(buffer);

	return success;
}

/**
 * Same as above, the only difference is that we set NULL the mtu_plateaus from
 * the local translate config.
 */
static bool translate_nulls_mtu(void)
{
	int error;
	unsigned char *buffer;
	size_t buffer_len;
	bool success = true;
	struct global_config config = { .translate.mtu_plateaus = NULL };
	struct global_config response = { .translate.mtu_plateaus = NULL };

	error = config_clone(&config);
	if (error)
		return false;

	/* lets modify our local config manually, jool's update functions wont update to null */
	config.translate.mtu_plateaus = NULL;
	config.translate.mtu_plateau_count = 0;

	error = serialize_global_config(&config, &buffer, &buffer_len);
	if (error)
		return false;

	error = deserialize_global_config(buffer, buffer_len, &response);
	if (error)
		return false;

	success &= compare_global_configs(&config, &response);

	/* the "compare_global_configs" will not evaluate the mtu_plateaus
	 * because of the plateau_count = 0
	 */
	success &= assert_null(config.translate.mtu_plateaus, "local config mtu_plateaus");
	success &= assert_null(response.translate.mtu_plateaus, "deserialized config mtu_plateaus");

	kfree(buffer);

	return success;
}

static bool init(void)
{
	if (is_error(fragdb_init()))
		return false;
	if (!init_full()) {
		fragdb_destroy();
		return false;
	}

	return true;
}

static void end(void)
{
	fragdb_destroy();
	end_full();
}

static int configproto_test_init(void)
{
	START_TESTS("Packet queue");

	INIT_CALL_END(init(), basic_test(), end(), "basic test");
	INIT_CALL_END(init(), translate_nulls_mtu(), end(), "nulls mtus");

	END_TESTS;
}

static void configproto_test_exit(void)
{
	/* No code. */
}

module_init(configproto_test_init);
module_exit(configproto_test_exit);
