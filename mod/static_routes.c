/** 
 * @file
 *
 * This module implements the feature mentioned in the RFC6146, 
 * about managing static routes. It allows to add a new entry in
 * the BIB and Session tables from Userspace.
 */

#include "nat64/mod/static_routes.h"
#include "nat64/mod/config.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"
#include <linux/slab.h>


/**
 * TODO (critical) ports are not being borrowed from the IPv4 pool!!!
 * We also need to check that pair6.remote and pair4.local belong to the pools =_=.
 */
int add_static_route(struct request_session *req)
{
	struct bib_entry *bib_by_ipv6, *bib_by_ipv4;
	struct session_entry *session_by_4, *session_by_6;

	struct bib_entry *bib = NULL;
	bool bib_is_new = false;
	struct session_entry *session = NULL;

	int error;

	spin_lock_bh(&bib_session_lock);

	session_by_4 = session_get_by_ipv4(&req->add.pair4, req->l4_proto);
	session_by_6 = session_get_by_ipv6(&req->add.pair6, req->l4_proto);

	if (session_by_6 != NULL && session_by_4 == NULL) {
		log_err(ERR_SESSION_PAIR6_REINSERT, "The requested ipv6 address pair is already in use.");
		error = -EEXIST;
		goto failure;

	} else if (session_by_6 == NULL && session_by_4 != NULL) {
		log_err(ERR_SESSION_PAIR4_REINSERT, "The requested ipv4 address pair is already in use.");
		error = -EEXIST;
		goto failure;

	} else if (session_by_6 != NULL && session_by_4 != NULL) {
		if (session_by_6 == session_by_4) {
			if (session_by_6->is_static) {
				log_err(ERR_SESSION_REINSERT, "The session entry already exists.");
				error = -EEXIST;
				goto failure;
			}
			session_by_6->is_static = true;
			goto success;

		} else {
			log_err(ERR_SESSION_DUAL_REINSERT, "Both address pairs are already in use.");
			error = -EEXIST;
			goto failure;
		}
	}

	bib_by_ipv6 = bib_get_by_ipv6(&req->add.pair6.remote, req->l4_proto);
	bib_by_ipv4 = bib_get_by_ipv4(&req->add.pair4.local, req->l4_proto);

	if (bib_by_ipv6 != NULL && bib_by_ipv4 == NULL) {
		log_err(ERR_BIB_ADDR6_REINSERT, "The requested remote addr6#port combination is already "
				"mapped to some other local addr4#port.");
		error = -EEXIST;
		goto failure;

	} else if (bib_by_ipv6 == NULL && bib_by_ipv4 != NULL) {
		log_err(ERR_BIB_ADDR4_REINSERT, "The requested local addr4#port combination is already "
				"mapped to some other remote addr6#port.");
		error = -EEXIST;
		goto failure;

	} else if (bib_by_ipv6 != NULL && bib_by_ipv4 != NULL) {
		if (bib_by_ipv6 == bib_by_ipv4) {
			bib = bib_by_ipv6;
			bib_is_new = false;
		} else {
			log_err(ERR_BIB_DUAL_REINSERT, "The local addr4#port and the remote addr6#port are "
					"already mapped.");
			error = -EEXIST;
			goto failure;
		}

	} else {
		bib = bib_create(&req->add.pair4.local, &req->add.pair6.remote);
		if (!bib) {
			log_err(ERR_ALLOC_FAILED, "Could NOT allocate a BIB entry.");
			error = -ENOMEM;
			goto failure;
		}

		error = bib_add(bib, req->l4_proto);
		if (error) {
			log_err(ERR_UNKNOWN_ERROR, "Could NOT add the BIB entry to the table.");
			goto failure;
		}

		bib_is_new = true;
	}

	session = session_create_static(&req->add.pair4, &req->add.pair6, bib, req->l4_proto);
	if (!session) {
		log_err(ERR_ALLOC_FAILED, "Could NOT allocate a session entry.");
		error = -ENOMEM;
		goto failure;
	}

	error = session_add(session);
	if (error) {
		log_err(ERR_UNKNOWN_ERROR, "Could NOT add the session entry to the table.");
		goto failure;
	}

	/* Fall through. */

success:
	spin_unlock_bh(&bib_session_lock);
	return 0;

failure:
	if (session)
		kfree(session);
	if (bib_is_new) {
		bib_remove(bib, req->l4_proto);
		kfree(bib);
	}
	spin_unlock_bh(&bib_session_lock);
	return error;
}

int delete_static_route(struct request_session *req)
{
	struct session_entry *session = NULL;

	spin_lock_bh(&bib_session_lock);
	switch (req->remove.l3_proto) {
	case PF_INET6:
		session = session_get_by_ipv6(&req->remove.pair6, req->l4_proto);
		break;
	case PF_INET:
		session = session_get_by_ipv4(&req->remove.pair4, req->l4_proto);
		break;
	default:
		spin_unlock_bh(&bib_session_lock);
		log_err(ERR_L3PROTO, "Unsupported network protocol: %u.", req->remove.l3_proto);
		return -EINVAL;
	}

	if (!session) {
		spin_unlock_bh(&bib_session_lock);
		log_err(ERR_SESSION_NOT_FOUND, "Could not find the session entry requested by the user.");
		return -ENOENT;
	}

	// I'm tempted to assert that the session is static here. Would that serve a purpose?

	if (!session_remove(session)) {
		spin_unlock_bh(&bib_session_lock);
		// Rather have a slight memory leak than damaged memory, so I'm not kfreeing session.
		log_err(ERR_UNKNOWN_ERROR, "Remove session call ended in failure, despite validations.");
		return -EINVAL;
	}

	kfree(session);
	spin_unlock_bh(&bib_session_lock);
	return 0;
}
