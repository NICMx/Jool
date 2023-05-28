#include "usr/nl/core.h"
#include "usr/nl/instance.h"

static struct jool_result print_entry(struct instance_entry_usr const *instance,
		void *arg)
{
	printf("- %s\n", instance->iname);
	return result_success();
}

static int display_instances(xlator_type xt)
{
	struct joolnl_socket sk;
	struct jool_result result;

	result = joolnl_setup(&sk, xt);
	if (result.error)
		return result.error;
	result = joolnl_instance_foreach(&sk, print_entry, NULL);
	joolnl_teardown(&sk);

	return result.error;
}

int main(int argc, char **argv)
{
	printf("SIIT instances:\n");
	display_instances(XT_SIIT);

	printf("NAT64 instances:\n");
	display_instances(XT_NAT64);

	return 0;
}
