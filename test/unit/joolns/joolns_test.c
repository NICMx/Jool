#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#include "framework/address.h"
#include "framework/unit_test.h"

#include "mod/common/atomic_config.h"
#include "mod/common/linux_version.h"
#include "mod/common/xlator.h"
#include "mod/common/db/eam.h"

/*
 * Er... this doesn't even try to test everything.
 * Most of the implementation is brain-dead anyway. I'm only concerned about
 * usable APIs and reference counts at the moment.
 */

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Xlator test.");

/** The network namespace where the test is being run. */
static struct net *ns;
/** Number of references that @ns had at the beginning of the test. */
static int old_refs;

int jstat_refcount(struct jool_stats *stats);

static int ns_refcount(struct net *ns)
{
#if LINUX_VERSION_AT_LEAST(5, 12, 0, 9999, 0)
	return refcount_read(&ns->ns.count);
#else
	return refcount_read(&ns->count);
#endif
}

struct validate_args {
	char *addr6;
	__u8 len6;
	char *addr4;
	__u8 len4;
	unsigned int count;
};

static int __validate(struct eamt_entry const *eam, void *__args)
{
	struct validate_args *args = __args;
	bool success = true;

	success &= ASSERT_UINT(0, args->count, "eam count");
	success &= ASSERT_ADDR6(args->addr6, &eam->prefix6.addr, "addr6");
	success &= ASSERT_UINT(args->len6, eam->prefix6.len, "len6");
	success &= ASSERT_ADDR4(args->addr4, &eam->prefix4.addr, "addr4");
	success &= ASSERT_UINT(args->len4, eam->prefix4.len, "len4");
	args->count++;

	return success ? 0 : -EINVAL;
}

static bool validate(char *expected_addr6, __u8 expected_len6,
		char *expected_addr4, __u8 expected_len4)
{
	struct xlator jool;
	struct validate_args args;
	int error;
	bool success = true;

	error = xlator_find_current(INAME_DEFAULT, XF_NETFILTER | XT_SIIT,
			&jool, NULL);
	if (error) {
		pr_info("xlator_find_current() threw %d\n", error);
		return false;
	}

	args.addr6 = expected_addr6;
	args.len6 = expected_len6;
	args.addr4 = expected_addr4;
	args.len4 = expected_len4;
	args.count = 0;

	if (eamt_foreach(jool.siit.eamt, __validate, &args, NULL))
		success = false;

	xlator_put(&jool);
	return success;
}

/**
 * Superfluous test over xlator. It's mostly just API manhandling so krefs can
 * be tested next.
 */
static bool simple_test(void)
{
	return validate("2001:db8::", 120, "192.0.2.0", 24);
}

/**
 * This used to be a "Superfluous test over the jparser," where "jparser" was
 * apparently an old name for the atomic config handler.
 * The interface became impractical to use by the unit framework, so I
 * downgraded this to another one of these EAMT tests.
 * It's better than nothing, I guess.
 */
static bool atomic_test(void)
{
	struct xlator jool;
	struct eamt_entry eam;
	int error;

	error = str_to_addr6("2001:db8:bbbb::", &eam.prefix6.addr);
	if (error)
		return false;
	eam.prefix6.len = 121;
	error = str_to_addr4("198.51.100.0", &eam.prefix4.addr);
	if (error)
		return false;
	eam.prefix4.len = 25;

	error = xlator_find_current(INAME_DEFAULT, XF_NETFILTER | XT_SIIT,
				&jool, NULL);
	if (error) {
		pr_info("xlator_find_current() threw %d\n", error);
		return false;
	}

	eamt_flush(jool.siit.eamt);
	error = eamt_add(jool.siit.eamt, &eam, true, false, NULL);
	xlator_put(&jool);
	if (error) {
		pr_info("eamt_add() threw %d\n", error);
		return false;
	}

	return validate("2001:db8:bbbb::", 121, "198.51.100.0", 25);
}

/**
 * Test the previous test handled krefs correctly.
 */
static bool krefs_test(void)
{
	struct xlator jool;
	int error;
	bool success = true;

	error = xlator_find_current(INAME_DEFAULT, XF_NETFILTER | XT_SIIT,
			&jool, NULL);
	if (error) {
		pr_info("xlator_find_current() threw %d\n", error);
		return false;
	}

	/* The database does not claim references to ns. */
	success &= ASSERT_INT(old_refs, ns_refcount(jool.ns), "ns kref");
	/* xlator DB's kref + the one we just took. */
	success &= ASSERT_INT(2, jstat_refcount(jool.stats), "stats kref");

	xlator_put(&jool);
	return success;
}

/**
 * Test the previous test handled krefs correctly. Assumes the xlator has been
 * deinitialized.
 */
static bool ns_only_krefs_test(void)
{
	return ASSERT_INT(old_refs, ns_refcount(ns), "ns kref");
}

static int setup(void)
{
	/*
	 * This whole test assumes nothing else will grab or return references
	 * towards @ns, but some kernels seem to spawn threads during module
	 * insertion that do. So we sleep two seconds to wait them out.
	 *
	 * Of course, this is not bulletproof. @ns can always change without
	 * warning, but at least this does improve the rate from almost
	 * guaranteed failure to almost guaranteed success.
	 */
	ssleep(2);

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		pr_err("Could not retrieve the current namespace.\n");
		return PTR_ERR(ns);
	}
	old_refs = ns_refcount(ns);

	return 0;
}

static void teardown(void)
{
	put_net(ns);
}

static int init(void)
{
	struct xlator jool;
	struct eamt_entry eam;
	int error;

	error = xlator_add(XF_NETFILTER | XT_SIIT, INAME_DEFAULT, NULL, &jool,
			NULL);
	if (error) {
		pr_info("xlator_add() threw %d\n", error);
		return error;
	}

	error = str_to_addr6("2001:db8::", &eam.prefix6.addr);
	if (error)
		goto fail;
	eam.prefix6.len = 120;
	error = str_to_addr4("192.0.2.0", &eam.prefix4.addr);
	if (error)
		goto fail;
	eam.prefix4.len = 24;
	error = eamt_add(jool.siit.eamt, &eam, true, false, NULL);
	if (error) {
		pr_info("eamt_add() threw %d\n", error);
		goto fail;
	}

	xlator_put(&jool);
	return 0;

fail:
	xlator_put(&jool);
	return error;
}

/**
 * This is not a test, but since it can fail, might as well declare it as one.
 */
static bool clean(void)
{
	return ASSERT_INT(0, xlator_rm(XT_SIIT, INAME_DEFAULT, NULL),
			"xlator_rm");
}

static int joolns_test_init(void)
{
	struct test_group test = {
		.name = "Xlator",
		.setup_fn = setup,
		.teardown_fn = teardown,
	};
	int error;

	test_group_begin(&test);

	error = init();
	if (error) {
		teardown();
		return error;
	}

	test_group_test(&test, simple_test, "xlator API");
	test_group_test(&test, krefs_test, "kfref checks 1");
	test_group_test(&test, atomic_test, "atomic config API");
	test_group_test(&test, krefs_test, "kfref checks 2");
	test_group_test(&test, clean, "clean");
	test_group_test(&test, ns_only_krefs_test, "kfref checks 3");

	return test_group_end(&test);
}

static void joolns_test_exit(void)
{
	/* No code. */
}

module_init(joolns_test_init);
module_exit(joolns_test_exit);
