#include "mod/common/xlator.h"

#include "mod/nat64/bib/db.h"

/*
 * xlator impersonator for BIB unit tests.
 */

int xlator_init(struct xlator *jool, struct net *ns, jframework fw, char *iname,
		struct config_prefix6 *pool6)
{
	memset(jool, 0, sizeof(*jool));

	jool->ns = ns;
	jool->fw = fw;
	strcpy(jool->iname, iname);

	jool->global = config_alloc(pool6);
	if (!jool->global)
		goto config_fail;
	jool->nat64.bib = bib_alloc();
	if (!jool->nat64.bib)
		goto bib_fail;

	return 0;

bib_fail:
	config_put(jool->global);
config_fail:
	return -ENOMEM;
}

void xlator_put(struct xlator *jool)
{
	bib_put(jool->nat64.bib);
	config_put(jool->global);
}
