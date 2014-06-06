/**
 * @file
 *
 * This module implements the feature mentioned in the RFC6146,
 * about managing static routes. It allows to add a new entry in
 * the BIB and Session tables from Userspace.
 */

#include "nat64/mod/static_routes.h"
#include "nat64/mod/config.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/session_db.h"
#include <linux/slab.h>


int add_static_route(struct request_bib *req)
{
	struct bib_entry *bib = NULL;
	int error;

	error = pool4_get(req->l4_proto, &req->add.ipv4);
	if (error) {
		log_warning("The IPv4 address and port could not be reserved from the pool."
				"Maybe they're being used by some other BIB entry?");
		return error;
	}

	bib = bib_create(&req->add.ipv4, &req->add.ipv6, true, req->l4_proto);
	if (!bib) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate the BIB entry.");
		error = -ENOMEM;
		goto bib_error;
	}

	error = bibdb_add(bib, req->l4_proto);
	if (error) {
		log_warning("The BIB entry could not be added to the database. Maybe an entry with the "
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
	pool4_return(req->l4_proto, &req->add.ipv4);
	return error;
}

int delete_static_route(struct request_bib *req)
{
	struct bib_entry *bib;
	int error = 0;

	switch (req->remove.l3_proto) {
	case L3PROTO_IPV6:
		error = bibdb_get_by_ipv6(&req->remove.ipv6, req->l4_proto, &bib);
		break;
	case L3PROTO_IPV4:
		error = bibdb_get_by_ipv4(&req->remove.ipv4, req->l4_proto, &bib);
		break;
	default:
		log_err(ERR_L3PROTO, "Unsupported network protocol: %u.", req->remove.l3_proto);
		error = -EINVAL;
		break;
	}

	if (error == -ENOENT) {
		log_err(ERR_BIB_NOT_FOUND, "Could not find the BIB entry requested by the user.");
		return error;
	}
	if (error)
		return error;

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
		log_err(ERR_INCOMPLETE_REMOVE, "Looks like some packet was using the BIB entry, "
				"so it couldn't be deleted immediately. If the entry still exists, "
				"you might want to try again.");
		return -EAGAIN;
	}

	return 0;
}
