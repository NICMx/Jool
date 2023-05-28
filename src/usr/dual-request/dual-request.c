#include "usr/nl/core.h"
#include "usr/nl/instance.h"

static struct jool_result print_entry(struct instance_entry_usr const *instance,
		void *arg)
{
	printf("- %s\n", instance->iname);
	return result_success();
}

int main(int argc, char **argv)
{
	struct joolnl_socket sk1;
	struct joolnl_socket sk2;
	struct jool_result result;

	printf("SIIT instances:\n");
	result = joolnl_setup(&sk1, XT_SIIT);
	if (result.error)
		return result.error;
	result = joolnl_instance_foreach(&sk1, print_entry, NULL);
	if (result.error)
		goto revert_sk1;

	printf("NAT64 instances:\n");
	result = joolnl_setup(&sk2, XT_NAT64);
	if (result.error)
		goto revert_sk1;
	result = joolnl_instance_foreach(&sk2, print_entry, NULL);

	joolnl_teardown(&sk1);
	joolnl_teardown(&sk2);
	return 0;

revert_sk1:
	joolnl_teardown(&sk1);
	return result.error;
}
