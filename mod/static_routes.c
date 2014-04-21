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
	struct bib_entry *bib_by_ipv6, *bib_by_ipv4;
	struct bib_entry *bib = NULL;
	int error;

	if (!pool4_contains(&req->add.ipv4.address)) {
		log_err(ERR_POOL6_NOT_FOUND, "The address '%pI4' does not belong to the IPv4 pool.",
				&req->add.ipv4.address);
		return -EINVAL;
	}

	/* Check if the BIB entry exists. */
	error = bibdb_get_by_ipv6(&req->add.ipv6, req->l4_proto, &bib_by_ipv6);
	if (!error) {
		bib = bib_by_ipv6;
		goto already_mapped;
	}
	if (error != -ENOENT)
		goto generic_error;

	error = bibdb_get_by_ipv4(&req->add.ipv4, req->l4_proto, &bib_by_ipv4);
	if (!error) {
		bib = bib_by_ipv4;
		goto already_mapped;
	}
	if (error != -ENOENT)
		goto generic_error;

	/* Borrow the address and port from the IPv4 pool. */
	if (is_error(pool4_get(req->l4_proto, &req->add.ipv4))) {
		/*
		 * This might happen if Filtering just reserved the address#port, but hasn't yet inserted
		 * the BIB entry to the table. This is because bib_session_lock doesn't cover the IPv4
		 * pool.
		 * Otherwise something's not returning borrowed address#ports to the pool, which is an
		 * error.
		 */
		log_err(ERR_BIB_REINSERT, "Port number %u from address %pI4 is taken from the IPv4 pool, "
				"but it wasn't found in the BIB. Please try again; if the problem persists, "
				"please report.", req->add.ipv4.l4_id, &req->add.ipv4.address);
		error = -EEXIST;
		goto failure;
	}

	/* Create and insert the entry. */
	bib = bib_create(&req->add.ipv4, &req->add.ipv6, true, req->l4_proto);
	if (!bib) {
		log_err(ERR_ALLOC_FAILED, "Could NOT allocate a BIB entry.");
		error = -ENOMEM;
		goto failure;
	}

	error = bibdb_add(bib, req->l4_proto);
	if (error) {
		log_err(ERR_UNKNOWN_ERROR, "Could NOT add the BIB entry to the table.");
		bib_kfree(bib);
		goto failure;
	}

	/*
	 * We do not call bib_return(bib) here, because we want the entry to hold a fake user so the
	 * timer doesn't delete it.
	 */

	return 0;

already_mapped:
	log_err(ERR_BIB_REINSERT, "%pI6c#%u is already mapped to %pI4#%u.",
			&bib->ipv6.address, bib->ipv6.l4_id,
			&bib->ipv4.address, bib->ipv4.l4_id);
	error = -EEXIST;
	bib_return(bib);
	goto failure;

generic_error:
	log_err(ERR_UNKNOWN_ERROR, "Error code %u while trying to interact with the BIB.",
			error);
	/* Fall through. */

failure:
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
				"so it couldn't be deleted. Please try again.");
		return -EAGAIN;
	}

	return 0;
}
