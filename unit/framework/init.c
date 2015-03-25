#include "nat64/unit/unit_test.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/session_db.h"

bool init_full(void)
{
	char *prefixes[] = { "3::/96" };
	int error;

	error = config_init(false);
	if (error)
		goto config_fail;
	error = pool6_init(prefixes, ARRAY_SIZE(prefixes));
	if (error)
		goto pool6_fail;
	error = pool4_init(NULL, 0);
	if (error)
		goto pool4_fail;
	error = pktqueue_init();
	if (error)
		goto pktqueue_fail;
	error = bibdb_init();
	if (error)
		goto bibdb_fail;
	error = sessiondb_init();
	if (error)
		goto sessiondb_fail;

	return true;

sessiondb_fail:
	bibdb_destroy();
bibdb_fail:
	pktqueue_destroy();
pktqueue_fail:
	pool4_destroy();
pool4_fail:
	pool6_destroy();
pool6_fail:
	config_destroy();
config_fail:
	return false;
}

void end_full(void)
{
	sessiondb_destroy();
	bibdb_destroy();
	pktqueue_destroy();
	pool4_destroy();
	pool6_destroy();
	config_destroy();
}
