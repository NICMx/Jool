#include "nat64/mod/common/namespace.h"
#include <linux/sched.h>
#include <linux/err.h>
#include "nat64/mod/common/types.h"

static struct net *jool_net;

int joolns_init(void)
{
	jool_net = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(jool_net)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(jool_net);
	}

	return 0;
}

void joolns_destroy(void)
{
	put_net(jool_net);
}

struct net *joolns_get(void)
{
	return jool_net;
}
