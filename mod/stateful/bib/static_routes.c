/**
 * @file
 *
 * This module implements the feature mentioned in the RFC6146,
 * about managing static routes. It allows to add a new entry in
 * the BIB and Session tables from Userspace.
 */

#include "nat64/mod/stateful/bib/static_routes.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/session/db.h"
#include <linux/slab.h>


static int validate_bib(int error, struct bib_entry *bib)
{
	if (!error) {
		log_err("%pI4#%u is already mapped to %pI6c#%u.",
				&bib->ipv4.l3, bib->ipv4.l4,
				&bib->ipv6.l3, bib->ipv6.l4);
		bibdb_return(bib);
		return -EEXIST;
	}

	if (error == -ESRCH)
		return 0;

	log_err("Error code %d while trying to figure out if the transport "
			"address is already being used by some other BIB"
			"entry.", error);
	return error;
}

int add_static_route(struct request_bib *request)
{
	struct bib_entry *bib = NULL;
	int error;

	if (!pool4db_contains_all(request->l4_proto, &request->add.addr4)) {
		log_err("The transport address (%pI4#%u) does not belong to "
				"the IPv4 pool. Please add it there first.",
				&request->add.addr4.l3, request->add.addr4.l4);
		return -EINVAL;
	}

	error = bibdb_get4(&request->add.addr4, request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	error = bibdb_get6(&request->add.addr6, request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	bib = bibentry_create(&request->add.addr4, &request->add.addr6, true,
			request->l4_proto);
	if (!bib) {
		log_err("Could not allocate the BIB entry.");
		return -ENOMEM;
	}

	error = bibdb_add(bib);
	if (error) {
		log_err("The BIB entry could not be added to the database, "
				"despite validations. This can happen if a "
				"conflicting entry appeared while I was "
				"trying to insert. Try again.");
		bibentry_kfree(bib);
		return error;
	}

	/*
	 * We do not call bib_return(bib) here, because we want the entry to
	 * hold a fake user so the timer doesn't delete it.
	 */

	return 0;
}

int delete_static_route(struct request_bib *request)
{
	struct ipv4_transport_addr *req4 = &request->rm.addr4;
	struct ipv6_transport_addr *req6 = &request->rm.addr6;
	struct bib_entry *bib;
	int error = 0;

	if (request->rm.addr6_set) {
		error = bibdb_get6(req6, request->l4_proto, &bib);
	} else if (request->rm.addr4_set) {
		error = bibdb_get4(req4, request->l4_proto, &bib);
	} else {
		log_err("You need to provide an address so I can find the "
				"entry you want to remove.");
		return -EINVAL;
	}

	if (error == -ESRCH) {
		log_err("The entry wasn't in the database.");
		return error;
	}
	if (error)
		return error;

	if (request->rm.addr6_set && request->rm.addr4_set) {
		if (!ipv4_transport_addr_equals(&bib->ipv4, req4)) {
			log_err("%pI6c#%u is mapped to %pI4#%u, not %pI4#%u.",
					&bib->ipv6.l3, bib->ipv6.l4,
					&bib->ipv4.l3, bib->ipv4.l4,
					&req4->l3, req4->l4);
			bibdb_return(bib);
			return -ESRCH;
		}
	}

	/* Remove the fake user. */
	if (bib->is_static) {
		bibdb_return(bib);
		bib->is_static = false;
	}

	/* Remove bib's sessions and their references. */
	error = sessiondb_delete_by_bib(bib);
	if (error) {
		bibdb_return(bib);
		return error;
	}

	/* Remove our own reference. */
	bibdb_return(bib);
	return 0;
}
