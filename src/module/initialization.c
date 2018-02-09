#include "xlator.h"
#include "nl/nl-handler.h"
#include "nat64/joold.h"
#include "nat64/timer.h"
#include "nat64/bib/db.h"
#include "nat64/pool4/rfc6056.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("IP/ICMP Translator (RFCs 7915 and 6146)");
MODULE_VERSION(JOOL_VERSION_STR);

static int jool_netdev_init_module(void)
{
	int error;

	error = rfc6056_init();
	if (error)
		goto rfc6056_fail;
	error = bib_init();
	if (error)
		goto bib_fail;
	error = joold_init();
	if (error)
		goto joold_fail;
	error = nlhandler_init();
	if (error)
		goto nlhandler_fail;
	// TODO this should happen last. Or not happen at all really.
	error = timer_init();
	if (error)
		goto timer_fail;

	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;

timer_fail:
	nlhandler_destroy();
nlhandler_fail:
	joold_terminate();
joold_fail:
	bib_destroy();
bib_fail:
	rfc6056_destroy();
rfc6056_fail:
	return error;
}

static void jool_netdev_cleanup_module(void)
{
	/* TODO destroy all instances */

	timer_destroy();
	nlhandler_destroy();
	joold_terminate();
	bib_destroy();
	rfc6056_destroy();

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_netdev_init_module);
module_exit(jool_netdev_cleanup_module);
