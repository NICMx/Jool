#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/json_parser.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/unit/unit_test.h"

/*
 * Er... this doesn't even try to test everything.
 * Most of the implementation is brain-dead anyway. I'm only concerned about
 * usable APIs and reference counts at the moment.
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("JoolNS test.");

static bool validate(char *expected_addr, __u8 expected_len)
{
	struct xlator jool;
	struct ipv6_prefix prefix;
	int error;
	bool success = true;

	error = joolns_get_current(&jool);
	if (error) {
		log_info("joolns_get_current() threw %d", error);
		return false;
	}

	error = pool6_peek(jool.pool6, &prefix);
	joolns_put(&jool);
	if (error) {
		log_info("pool6_peek() threw %d", error);
		return false;
	}

	success &= ASSERT_ADDR6(expected_addr, &prefix.address, "addr");
	success &= ASSERT_UINT(expected_len, prefix.len, "len");

	return success;
}

/**
 * Superfluous test over joolns. It's mostly just API manhandling so krefs can
 * be tested next.
 */
static bool simple_test(void)
{
	return validate("2001:db8::", 96);
}

/**
 * Superfluous test over the jparser. It's mostly just API manhandling so krefs
 * can be tested next.
 */
static bool atomic_test(void)
{
	struct xlator *new;
	struct request_hdr hdr;
	unsigned char request[sizeof(__u16) + sizeof(struct ipv6_prefix)];
	__u16 type;
	struct ipv6_prefix prefix;
	int error;
	bool success = false;

	error = jparser_init(&new);
	if (error) {
		log_info("jparser_init() threw %d", error);
		return false;
	}

	error = str_to_addr6("2001:db8:bbbb::", &prefix.address);
	if (error)
		goto end;
	prefix.len = 56;

	hdr.length = sizeof(hdr) + sizeof(request);
	type = SEC_POOL6;
	memcpy(&request[0], &type, sizeof(__u16));
	memcpy(&request[2], &prefix, sizeof(prefix));

	error = jparser_handle(new, &hdr, request);
	if (error) {
		log_info("jparser_handle() 1 threw %d", error);
		goto end;
	}

	hdr.length = sizeof(hdr) + sizeof(__u16);
	type = SEC_COMMIT;
	memcpy(&request[0], &type, sizeof(__u16));

	error = jparser_handle(new, &hdr, request);
	if (error) {
		log_info("jparser_handle() 2 threw %d", error);
		goto end;
	}

	success = validate("2001:db8:bbbb::", 56);

end:
	jparser_destroy(new);
	return success;
}

/**
 * Test the previous test handled krefs correctly.
 *
 * @ns_kref expected references towards the current context's struct net.
 */
static bool krefs_test(int ns_kref)
{
	struct xlator jool;
	int error;
	bool success = true;

	error = joolns_get_current(&jool);
	if (error) {
		log_info("joolns_get_current() threw %d", error);
		return false;
	}

	/* @ns_kref + the one we just took. */
	success &= ASSERT_INT(ns_kref + 1, atomic_read(&jool.ns->count), "ns kref");
	/* joolns's kref + the one we just took. */
	success &= ASSERT_INT(2, atomic_read(&jool.pool6->refcount.refcount), "pool6 kref");

	joolns_put(&jool);
	return success;
}

/**
 * Test the previous test handled krefs correctly. Assumes the joolns has been
 * deinitialized.
 */
static bool ns_only_krefs_test(int ns_kref, struct net *ns)
{
	return ASSERT_INT(ns_kref, atomic_read(&ns->count), "ns kref");
}

enum session_fate tcp_expired_cb(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static int init(void)
{
	struct xlator jool;
	struct ipv6_prefix prefix;
	int error;

	error = joolns_init();
	if (error) {
		log_info("joolns_init() threw %d", error);
		return error;
	}
	error = joolns_add();
	if (error) {
		log_info("joolns_add() threw %d", error);
		goto fail;
	}
	error = joolns_get_current(&jool);
	if (error) {
		log_info("joolns_get_current() threw %d", error);
		goto fail;
	}

	error = str_to_addr6("2001:db8::", &prefix.address);
	if (error)
		goto fail;
	prefix.len = 96;

	error = pool6_add(jool.pool6, &prefix);
	if (error) {
		log_info("pool6_add() threw %d", error);
		goto fail;
	}

	joolns_put(&jool);
	return 0;

fail:
	joolns_destroy();
	return error;
}

/**
 * This is not a test, but since it can fail, might as well declare it as one.
 */
static bool destroy(void)
{
	bool success;
	success = ASSERT_INT(0, joolns_rm(), "joolns_rm");
	joolns_destroy();
	return success;
}

int init_module(void)
{
	struct net *ns;
	int old;
	int error;
	START_TESTS("JoolNS");

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}
	old = atomic_read(&ns->count);

	error = init();
	if (error) {
		put_net(ns);
		return error;
	}

	CALL_TEST(simple_test(), "joolns API");
	CALL_TEST(krefs_test(old + 1), "kfref checks 1");
	CALL_TEST(atomic_test(), "atomic config API");
	CALL_TEST(krefs_test(old + 1), "kfref checks 2");
	CALL_TEST(destroy(), "destroy");
	CALL_TEST(ns_only_krefs_test(old, ns), "kfref checks 3");

	put_net(ns);
	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
