#include "nat64/unit/unit_test.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/filtering_and_updating.h"

bool init_full(void)
{
	char *prefixes6[] = { "3::/96" };
	char *prefixes4[] = { "192.0.2.2/32" };

	if (config_init())
		goto config_fail;
	if (pool6_init(prefixes6, ARRAY_SIZE(prefixes6)))
		goto pool6_fail;
	if (pool4db_init(16, prefixes4, ARRAY_SIZE(prefixes4)))
		goto pool4_fail;
	if (filtering_init())
		goto filtering_fail;

	return true;

filtering_fail:
	pool4db_destroy();
pool4_fail:
	pool6_destroy();
pool6_fail:
	config_destroy();
config_fail:
	return false;
}

void end_full(void)
{
	filtering_destroy();
	pool4db_destroy();
	pool6_destroy();
	config_destroy();
}
