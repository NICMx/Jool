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

/* TODO this is wrong. It doesn't account for dynamic entries and might try to kfree a sessioned bib under heavy concurrence. */
int delete_static_route(struct request_bib *req)
{
	struct bib_entry *bib;
	int s = 0;
	int error = 0;

	switch (req->remove.l3_proto) {
	case L3PROTO_IPV6:
		error = bibdb_get_by_ipv6(&req->remove.ipv6, req->l4_proto, &bib);
		if (error)
			goto end;
		break;
	case L3PROTO_IPV4:
		error = bibdb_get_by_ipv4(&req->remove.ipv4, req->l4_proto, &bib);
		if (error)
			goto end;
		break;
	default:
		log_err(ERR_L3PROTO, "Unsupported network protocol: %u.", req->remove.l3_proto);
		error = -EINVAL;
		goto end;
	}

	if (!bib) {
		log_err(ERR_BIB_NOT_FOUND, "Could not find the BIB entry requested by the user.");
		error = -ENOENT;
		goto end;
	}

	/*
	 * If everything is going smoothly, bib's refcounter should be 1 + 1 + x, where the first one is
	 * the fake user, the second is the reference we just got by calling bibdb_get*, and x is the
	 * bib's session count.
	 */

	/*
	 * I'm tempted to assert that the entry is static here. Would that serve a purpose?
	 * Nah.
	 */

	s = atomic_read(&bib->refcounter.refcount) - 2;
	log_debug("The BIB has %d sessions.", s);

	error = sessiondb_delete_by_bib(bib);
	if (error)
		goto error;

	s = atomic_read(&bib->refcounter.refcount) - 2;
	log_debug("The BIB ended with %d sessions.", s);

	error = bibdb_remove(bib, req->l4_proto);
	if (error) {
		log_err(ERR_UNKNOWN_ERROR, "Remove bib entry call ended with error code %d, "
				"despite validations.", error);
		goto error;
	}

	bib_kfree(bib);
	/* Fall through. */

end:
	return error;

error:
	bib_return(bib);
	return error;
}
