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
enum error_code add_static_route(struct request_session *req)
{
	struct bib_entry *bib_by_ipv6, *bib_by_ipv4;
	struct session_entry *session_by_4, *session_by_6;

	struct bib_entry *bib = NULL;
	bool bib_is_new = false;
	struct session_entry *session = NULL;

	enum error_code result;

	spin_lock_bh(&bib_session_lock);

	session_by_4 = session_get_by_ipv4(&req->add.pair4, req->l4_proto);
	session_by_6 = session_get_by_ipv6(&req->add.pair6, req->l4_proto);

	if (session_by_6 != NULL && session_by_4 == NULL) {
		result = ERR_SESSION_PAIR6_REINSERT;
		log_err(result, "The requested local-remote ipv6 addresses are already in use.");
		goto failure;

	} else if (session_by_6 == NULL && session_by_4 != NULL) {
		result = ERR_SESSION_PAIR4_REINSERT;
		log_err(result, "The requested local-remote ipv4 addresses are already in use.");
		goto failure;

	} else if (session_by_6 != NULL && session_by_4 != NULL) {
		if (session_by_6 == session_by_4) {
			if (session_by_6->is_static) {
				result = ERR_SESSION_REINSERT;
				log_err(result, "The session entry is already on the table.");
				goto failure;
			}
			session_by_6->is_static = true;
			goto success;

		} else {
			result = ERR_SESSION_DUAL_REINSERT;
			log_err(result, "Both address pairs are already in use in the table.");
			goto failure;
		}
	}

	bib_by_ipv6 = bib_get_by_ipv6(&req->add.pair6.remote, req->l4_proto);
	bib_by_ipv4 = bib_get_by_ipv4(&req->add.pair4.local, req->l4_proto);

	if (bib_by_ipv6 != NULL && bib_by_ipv4 == NULL) {
		result = ERR_BIB_ADDR6_REINSERT;
		log_err(result, "The requested remote addr6#port combination is already mapped "
				"to some other local addr4#port.");
		goto failure;

	} else if (bib_by_ipv6 == NULL && bib_by_ipv4 != NULL) {
		result = ERR_BIB_ADDR4_REINSERT;
		log_err(result, "The requested local addr4#port combination is already mapped "
				"to some other remote addr6#port.");
		goto failure;

	} else if (bib_by_ipv6 != NULL && bib_by_ipv4 != NULL) {
		if (bib_by_ipv6 == bib_by_ipv4) {
			bib = bib_by_ipv6;
			bib_is_new = false;
		} else {
			result = ERR_BIB_DUAL_REINSERT;
			log_err(result, "The local addr4#port and the remote addr6#port are already mapped.");
			goto failure;
		}

	} else {
		bib = bib_create(&req->add.pair4.local, &req->add.pair6.remote);
		if (!bib) {
			result = ERR_ALLOC_FAILED;
			log_err(result, "Could NOT allocate a BIB entry.");
			goto failure;
		}

		result = bib_add(bib, req->l4_proto);
		if (result != ERR_SUCCESS) {
			log_err(result, "Could NOT add the BIB entry to the table.");
			goto failure;
		}

		bib_is_new = true;
	}

	session = session_create_static(&req->add.pair4, &req->add.pair6, bib, req->l4_proto);
	if (!session) {
		result = ERR_ALLOC_FAILED;
		log_err(result, "Could NOT allocate a session entry.");
		goto failure;
	}

	result = session_add(session);
	if (result != ERR_SUCCESS) {
		log_err(result, "Could NOT add the session entry to the table.");
		goto failure;
	}

	/* Fall through. */

success:
	spin_unlock_bh(&bib_session_lock);
	return ERR_SUCCESS;

failure:
	if (session)
		kfree(session);
	if (bib_is_new) {
		bib_remove(bib, req->l4_proto);
		kfree(bib);
	}
	spin_unlock_bh(&bib_session_lock);
	return result;
}

enum error_code delete_static_route(struct request_session *req)
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
		return ERR_L3PROTO;
	}

	if (!session) {
		spin_unlock_bh(&bib_session_lock);
		log_err(ERR_SESSION_NOT_FOUND, "Could not find the session entry requested by the user.");
		return ERR_SESSION_NOT_FOUND;
	}

	// I'm tempted to assert that the session is static here. Would that serve a purpose?

	if (!session_remove(session)) {
		spin_unlock_bh(&bib_session_lock);
		// Rather have a slight memory leak than damaged memory, so I'm not kfreeing session.
		log_err(ERR_UNKNOWN_ERROR, "Remove session call ended in failure, despite validations.");
		return ERR_UNKNOWN_ERROR;
	}

	kfree(session);
	spin_unlock_bh(&bib_session_lock);
	return ERR_SUCCESS;
}

enum error_code print_bib_table(union request_bib *request, __u16 *count_out,
		struct bib_entry_us **bibs_us_out)
{
	struct bib_entry **bibs_ks = NULL; // ks = kernelspace. Array of pointers to bib entries.
	struct bib_entry_us *bibs_us = NULL; // us = userspace. Array of bib entries.
	__s32 counter, count;

	spin_lock_bh(&bib_session_lock);
	count = bib_to_array(request->display.l4_proto, &bibs_ks);
	spin_unlock_bh(&bib_session_lock);
	if (count == 0) {
		*count_out = 0;
		*bibs_us_out = NULL;
		return ERR_SUCCESS;
	}
	if (count < 0)
		goto kmalloc_fail;

	bibs_us = kmalloc(count * sizeof(*bibs_us), GFP_ATOMIC);
	if (!bibs_us)
		goto kmalloc_fail;

	for (counter = 0; counter < count; counter++) {
		bibs_us[counter].ipv4 = bibs_ks[counter]->ipv4;
		bibs_us[counter].ipv6 = bibs_ks[counter]->ipv6;
	}

	kfree(bibs_ks);
	*count_out = count;
	*bibs_us_out = bibs_us;
	return ERR_SUCCESS;

kmalloc_fail:
	kfree(bibs_ks);
	return ERR_ALLOC_FAILED;
}

enum error_code print_session_table(struct request_session *request, __u16 *count_out,
		struct session_entry_us **sessions_us_out)
{
	struct session_entry **sessions_ks = NULL;
	struct session_entry_us *sessions_us = NULL;
	__s32 counter, count;
	unsigned int now;

	spin_lock_bh(&bib_session_lock);
	count = session_to_array(request->l4_proto, &sessions_ks);
	spin_unlock_bh(&bib_session_lock);
	if (count == 0) {
		*count_out = 0;
		*sessions_us_out = NULL;
		return ERR_SUCCESS;
	}
	if (count < 0)
		goto kmalloc_fail;

	sessions_us = kmalloc(count * sizeof(*sessions_us), GFP_ATOMIC);
	if (!sessions_us)
		goto kmalloc_fail;

	now = jiffies_to_msecs(jiffies);

	for (counter = 0; counter < count; counter++) {
		sessions_us[counter].ipv6 = sessions_ks[counter]->ipv6;
		sessions_us[counter].ipv4 = sessions_ks[counter]->ipv4;
		sessions_us[counter].is_static = sessions_ks[counter]->is_static;
		sessions_us[counter].dying_time = sessions_ks[counter]->dying_time - now;
		sessions_us[counter].l4_proto = sessions_ks[counter]->l4_proto;
	}

	kfree(sessions_ks);
	*count_out = count;
	*sessions_us_out = sessions_us;
	return ERR_SUCCESS;

kmalloc_fail:
	kfree(sessions_ks);
	return ERR_ALLOC_FAILED;
}
