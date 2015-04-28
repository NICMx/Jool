/**
 * @file
 *
 * This module implements the feature mentioned in the RFC6146,
 * about managing static routes. It allows to add a new entry in
 * the BIB and Session tables from Userspace.
 */

#include "nat64/mod/stateful/static_routes.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/session_db.h"
#include <linux/slab.h>


static int validate_bib(int error, struct bib_entry *bib)
{
	if (!error) {
		log_err("%pI4#%u is already mapped to %pI6c#%u.",
				&bib->ipv4.l3, bib->ipv4.l4,
				&bib->ipv6.l3, bib->ipv6.l4);
		bib_return(bib);
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

	error = pool4_contains_transport_addr(&request->add.addr4);
	if (error) {
		log_err("Looks like that transport address does not belong to "
				"the IPv4 pool. Please add it there first.");
		return error;
	}

	error = bibdb_get4(&request->add.addr4, request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	error = bibdb_get6(&request->add.addr6, request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	bib = bib_create(&request->add.addr4, &request->add.addr6, true,
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
		bib_kfree(bib);
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
	struct ipv4_transport_addr *req4 = &request->remove.addr4;
	struct ipv6_transport_addr *req6 = &request->remove.addr6;
	struct bib_entry *bib;
	int error = 0;

	if (request->remove.addr6_set) {
		error = bibdb_get6(req6, request->l4_proto, &bib);
	} else if (request->remove.addr4_set) {
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

	if (request->remove.addr6_set && request->remove.addr4_set) {
		if (!ipv4_transport_addr_equals(&bib->ipv4, req4)) {
			log_err("%pI6c#%u is mapped to %pI4#%u, not %pI4#%u.",
					&bib->ipv6.l3, bib->ipv6.l4,
					&bib->ipv4.l3, bib->ipv4.l4,
					&req4->l3, req4->l4);
			bib_return(bib);
			return -ESRCH;
		}
	}

	/* Remove the fake user. */
	if (bib->is_static) {
		bib_return(bib);
		bib->is_static = false;
	}

	/* Remove bib's sessions and their references. */
	error = sessiondb_delete_by_bib(bib);
	if (error) {
		bib_return(bib);
		return error;
	}

	/* Remove our own reference. */
	if (bib_return(bib) == 0) {
		log_err("Looks like some packet was using the BIB entry, "
				"so it couldn't be deleted immediately. "
				"If the entry still exists, "
				"you might want to try again.");
		return -EAGAIN;
	}

	return 0;
}
