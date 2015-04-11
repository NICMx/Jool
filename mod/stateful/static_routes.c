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


int add_static_route(struct request_bib *req)
{
	struct bib_entry *bib = NULL;
	int error;

	error = pool4_get(req->l4_proto, &req->add.addr4);
	if (error) {
		log_err("The IPv4 address and port could not be reserved from the pool. "
				"Maybe the IPv4 address you provided does not belong to the pool. "
				"Or maybe they're being used by some other BIB entry?");
		return error;
	}

	bib = bib_create(&req->add.addr4, &req->add.addr6, true, req->l4_proto);
	if (!bib) {
		log_err("Could not allocate the BIB entry.");
		error = -ENOMEM;
		goto bib_error;
	}

	error = bibdb_add(bib);
	if (error) {
		log_err("The BIB entry could not be added to the database. Maybe an entry with the "
				"same IPv4 and/or IPv6 transport address already exists?");
		bib_kfree(bib);
		goto bib_error;
	}

	/*
	 * We do not call bib_return(bib) here, because we want the entry to hold a fake user so the
	 * timer doesn't delete it.
	 */

	return 0;

bib_error:
	pool4_return(req->l4_proto, &req->add.addr4);
	return error;
}

int delete_static_route(struct request_bib *req)
{
	struct bib_entry *bib;
	int error = 0;

	if (req->remove.addr6_set) {
		error = bibdb_get_by_ipv6(&req->remove.addr6, req->l4_proto, &bib);
	} else if (req->remove.addr4_set) {
		error = bibdb_get_by_ipv4(&req->remove.addr4, req->l4_proto, &bib);
	} else {
		log_err("You need to provide an address so I can find the entry you want to remove.");
		return -EINVAL;
	}

	if (error == -ESRCH) {
		log_err("Could not find the BIB entry requested by the user.");
		return error;
	}
	if (error)
		return error;

	if (req->remove.addr6_set && req->remove.addr4_set) {
		if (!ipv4_transport_addr_equals(&bib->ipv4, &req->remove.addr4)) {
			log_err("There's no BIB entry with BOTH of the addresses you requested.");
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

	/* Remove our own reference. If it was the last one, the entry should be no more. */
	if (bib_return(bib) == 0) {
		log_err("Looks like some packet was using the BIB entry, "
				"so it couldn't be deleted immediately. If the entry still exists, "
				"you might want to try again.");
		return -EAGAIN;
	}

	return 0;
}
