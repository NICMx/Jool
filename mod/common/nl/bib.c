#include "nat64/mod/common/nl/bib.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"

static int bib_entry_to_userspace(struct bib_entry *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;

	struct bib_entry_usr entry_usr;

	entry_usr.addr4 = entry->ipv4;
	entry_usr.addr6 = entry->ipv6;
	entry_usr.l4_proto = entry->l4_proto;
	entry_usr.is_static = entry->is_static;

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_bib_display(struct bib *db, struct genl_info *info,
		struct request_bib *request)
{
	struct nlcore_buffer buffer;
	struct ipv4_transport_addr *addr4;
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Sending BIB to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	addr4 = request->display.addr4_set ? &request->display.addr4 : NULL;
	error = bibdb_foreach(db, request->l4_proto, bib_entry_to_userspace,
			&buffer, addr4);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_bib_count(struct bib *db, struct genl_info *info,
		struct request_bib *request)
{
	int error = 0;
	__u64 count;

	log_debug("Returning BIB count.");
	error = bibdb_count(db, request->l4_proto, &count);
	if (error)
		return nlcore_respond(info, error);

	return nlcore_respond_struct(info, &count, sizeof(count));
}

static int handle_bib_add(struct xlator *jool, struct request_bib *request)
{
	struct bib_entry *bib;
	struct bib_entry *old;
	int error;

	if (verify_superpriv())
		return -EPERM;

	log_debug("Adding BIB entry.");

	if (!pool4db_contains(jool->nat64.pool4, jool->ns, request->l4_proto,
			&request->add.addr4)) {
		log_err("The transport address '%pI4#%u' does not belong to pool4.\n"
				"Please add it there first.",
				&request->add.addr4.l3, request->add.addr4.l4);
		return -EINVAL;
	}

	bib = bibentry_create(&request->add.addr4, &request->add.addr6, true,
			request->l4_proto);
	if (!bib) {
		log_err("Could not allocate the BIB entry.");
		return -ENOMEM;
	}

	error = bibdb_add(jool->nat64.bib, bib, &old);
	if (error == -EEXIST) {
		log_err("[%pI6c#%u|%pI4#%u] collides with [%pI6c#%u|%pI4#%u].",
				&bib->ipv6.l3, bib->ipv6.l4,
				&bib->ipv4.l3, bib->ipv4.l4,
				&old->ipv6.l3, old->ipv6.l4,
				&old->ipv4.l3, old->ipv4.l4);
		bibentry_put_thread(bib, true);
		bibentry_put_thread(old, false);
		return error;
	}
	if (error) {
		log_err("Unknown error (%d) during the entry add.", error);
		bibentry_put_thread(bib, true);
		return error;
	}

	bibentry_get_db(bib); /* Add a fake user (for staticness) */
	bibentry_put_thread(bib, false);

	return 0;
}

static int handle_bib_rm(struct xlator *jool, struct request_bib *request)
{
	struct ipv4_transport_addr *req4 = &request->rm.addr4;
	struct ipv6_transport_addr *req6 = &request->rm.addr6;
	struct bib_entry *bib;
	int error;

	if (verify_superpriv())
		return -EPERM;

	log_debug("Removing BIB entry.");

	if (request->rm.addr6_set) {
		error = bibdb_find6(jool->nat64.bib, req6, request->l4_proto, &bib);
	} else if (request->rm.addr4_set) {
		error = bibdb_find4(jool->nat64.bib, req4, request->l4_proto, &bib);
	} else {
		log_err("You need to provide an address so I can find the entry you want to remove.");
		return -EINVAL;
	}

	if (error == -ESRCH) {
		log_err("The entry wasn't in the database.");
		return error;
	}
	if (error)
		return error;

	if (request->rm.addr6_set && request->rm.addr4_set) {
		if (!taddr4_equals(&bib->ipv4, req4)) {
			log_err("%pI6c#%u is mapped to %pI4#%u, not %pI4#%u.",
					&bib->ipv6.l3, bib->ipv6.l4,
					&bib->ipv4.l3, bib->ipv4.l4,
					&req4->l3, req4->l4);
			bibentry_put_thread(bib, false);
			return -ESRCH;
		}
	}

	/*
	 * Remove the fake user.
	 *
	 * TODO (issue204) This is kind of bad, though not incorrect just yet.
	 * In principle, "is_static" is supposed to only be touched while
	 * holding the BIB table lock.
	 * However, it just so happens that every r/w on is_static is currently
	 * also being protected by the configuration mutex. (The one in
	 * nl_handler2.c).
	 * So... for the sake of good coding practices, please move this to a
	 * spinlock-protected area the next time you refactor BIB.
	 *
	 * The next planned BIB refactor happens when I fix #204 (which is
	 * probably going to happen in another revision release), hence the
	 * "issue204" priority.
	 */
	if (bib->is_static) {
		bibentry_put_db(bib);
		bib->is_static = false;
	}

	/* Remove bib's sessions and their references. */
	error = sessiondb_delete_by_bib(jool->nat64.session, bib);

	/* Remove our own reference. */
	bibentry_put_thread(bib, false);
	return error;
}

int handle_bib_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	struct request_bib *request = (struct request_bib *)(jool_hdr + 1);
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have BIBs.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_bib_display(jool->nat64.bib, info, request);
	case OP_COUNT:
		return handle_bib_count(jool->nat64.bib, info, request);
	case OP_ADD:
		error = handle_bib_add(jool, request);
		break;
	case OP_REMOVE:
		error = handle_bib_rm(jool, request);
		break;
	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
