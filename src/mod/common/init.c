#include "mod/common/init.h"

#include <linux/module.h>
#include <linux/refcount.h>

#include "mod/common/joold.h"
#include "mod/common/log.h"
#include "mod/common/timer.h"
#include "mod/common/xlator.h"
#include "mod/common/db/bib/db.h"
#include "mod/common/db/pool4/rfc6056.h"
#include "mod/common/nl/nl_handler.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("IP/ICMP Translation (Core)");
MODULE_VERSION(JOOL_VERSION_STR);

static unsigned int siit_refs = 0;
static unsigned int nat64_refs = 0;
static DEFINE_MUTEX(lock);

static int setup_common_modules(void)
{
	int error;

	log_debug("Initializing common modules.");
	error = xlator_setup();
	if (error)
		return error;
	error = nlhandler_setup();
	if (error)
		xlator_teardown();

	return error;
}

static void teardown_common_modules(void)
{
	log_debug("Tearing down common modules.");
	nlhandler_teardown();
	xlator_teardown();
}

static int setup_nat64_modules(void (*defrag_enable)(struct net *ns))
{
	int error;

	log_debug("Initializing NAT64 modules.");

	error = bib_setup();
	if (error)
		goto bib_fail;
	error = joold_setup();
	if (error)
		goto joold_fail;
	error = rfc6056_setup();
	if (error)
		goto rfc6056_fail;
	error = jtimer_setup();
	if (error)
		goto jtimer_fail;

	xlator_set_defrag(defrag_enable);
	return 0;

jtimer_fail:
	rfc6056_teardown();
rfc6056_fail:
	joold_teardown();
joold_fail:
	bib_teardown();
bib_fail:
	return error;
}

static void teardown_nat64_modules(void)
{
	log_debug("Tearing down NAT64 modules.");
	jtimer_teardown();
	rfc6056_teardown();
	joold_teardown();
	bib_teardown();
}

int jool_siit_get(void)
{
	mutex_lock(&lock);
	siit_refs++;
	mutex_unlock(&lock);
	return 0;
}
EXPORT_SYMBOL_GPL(jool_siit_get);

void jool_siit_put(void)
{
	mutex_lock(&lock);
	if (!WARN(siit_refs == 0, "Too many jool_siit_put()s!"))
		siit_refs--;
	mutex_unlock(&lock);
}
EXPORT_SYMBOL_GPL(jool_siit_put);

int jool_nat64_get(void (*defrag_enable)(struct net *ns))
{
	int error = 0;
	mutex_lock(&lock);

	nat64_refs++;
	if (nat64_refs == 1)
		error = setup_nat64_modules(defrag_enable);

	mutex_unlock(&lock);
	return error;
}
EXPORT_SYMBOL_GPL(jool_nat64_get);

void jool_nat64_put(void)
{
	mutex_lock(&lock);

	if (WARN(nat64_refs == 0, "Too many jool_nat64_put()s!"))
		goto end;

	nat64_refs--;
	if (nat64_refs == 0)
		teardown_nat64_modules();

end:	mutex_unlock(&lock);
}
EXPORT_SYMBOL_GPL(jool_nat64_put);

bool is_siit_enabled(void)
{
	int refs;

	mutex_lock(&lock);
	refs = siit_refs;
	mutex_unlock(&lock);

	return !!refs;
}

bool is_nat64_enabled(void)
{
	int refs;

	mutex_lock(&lock);
	refs = nat64_refs;
	mutex_unlock(&lock);

	return !!refs;
}

static int __init jool_init(void)
{
	int error;

	log_debug("Inserting Core Jool...");

	error = setup_common_modules();
	if (error)
		return error;

	log_info("Core Jool v" JOOL_VERSION_STR " module inserted.");
	return 0;
}

static void __exit jool_exit(void)
{
	teardown_common_modules();

#ifdef JKMEMLEAK
	wkmalloc_print_leaks();
	wkmalloc_teardown();
#endif

	log_info("Core Jool v" JOOL_VERSION_STR " module removed.");
}

module_init(jool_init);
module_exit(jool_exit);
