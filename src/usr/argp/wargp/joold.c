#include "usr/argp/wargp/joold.h"

#include "usr/nl/joold.h"
#include "usr/argp/log.h"
#include "usr/argp/xlator_type.h"

int handle_joold_advertise(char *iname, int argc, char **argv, void *arg)
{
	struct jool_socket sk;
	struct jool_result result;

	result = netlink_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	result = joold_advertise(&sk, iname);

	netlink_teardown(&sk);
	return pr_result(&result);
}

void autocomplete_joold_advertise(void *args)
{
	/* joold advertise has no arguments. */
}
