#include "nat64/mod/common/nl/bib.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"

static const enum config_mode COMMAND = MODE_BIB;

static int bib_entry_to_userspace(struct bib_entry *entry, void *arg)
{
	struct nl_core_buffer *buffer = (struct nl_core_buffer *)arg;

	struct bib_entry_usr entry_usr;

	entry_usr.addr4 = entry->ipv4;
	entry_usr.addr6 = entry->ipv6;
	entry_usr.is_static = entry->is_static;

	return nl_core_write_to_buffer(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_bib_display(struct bib *db, struct genl_info *info,
		struct request_bib *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_transport_addr *addr4;
	int error;

	log_debug("Sending BIB to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());
	if (error)
		return nl_core_respond_error(info, COMMAND, error);

	addr4 = request->display.addr4_set ? &request->display.addr4 : NULL;
	error = bibdb_foreach(db, request->l4_proto, bib_entry_to_userspace,
			buffer, addr4);
	buffer->pending_data = error > 0;
	error = (error >= 0)
			? nl_core_send_buffer(info, COMMAND, buffer)
			: nl_core_respond_error(info, COMMAND, error);

	nl_core_free_buffer(buffer);
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
		return nl_core_respond_error(info, COMMAND, error);

	return nlcore_respond_struct(info, COMMAND, &count, sizeof(count));
}

static int validate_bib(int error, struct bib_entry *bib)
{
	if (!error) {
		log_err("%pI4#%u is already mapped to %pI6c#%u.",
				&bib->ipv4.l3, bib->ipv4.l4,
				&bib->ipv6.l3, bib->ipv6.l4);
		bibentry_put(bib);
		return -EEXIST;
	}

	if (error == -ESRCH)
		return 0;

	log_err("Errcode %d while trying to figure out if the entry already exists.",
			error);
	return error;
}

static int handle_bib_add(struct xlator *jool, struct request_bib *request)
{
	struct bib_entry *bib = NULL;
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

	error = bibdb_find4(jool->nat64.bib, &request->add.addr4,
			request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	error = bibdb_find6(jool->nat64.bib, &request->add.addr6,
			request->l4_proto, &bib);
	error = validate_bib(error, bib);
	if (error)
		return error;

	bib = bibentry_create(&request->add.addr4, &request->add.addr6, true,
			request->l4_proto);
	if (!bib) {
		log_err("Could not allocate the BIB entry.");
		return -ENOMEM;
	}

	error = bibdb_add(jool->nat64.bib, bib);
	if (error) {
		log_err("The BIB entry could not be added to the database, despite validations.\n"
				"This can happen if a conflicting entry appeared while I was trying to insert.\n"
				"Try again.");
		bibentry_put(bib);
		return error;
	}

	/*
	 * We do not call bib_return(bib) here, because we want the entry to
	 * hold a fake user so the timer doesn't delete it.
	 */

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
		if (!ipv4_transport_addr_equals(&bib->ipv4, req4)) {
			log_err("%pI6c#%u is mapped to %pI4#%u, not %pI4#%u.",
					&bib->ipv6.l3, bib->ipv6.l4,
					&bib->ipv4.l3, bib->ipv4.l4,
					&req4->l3, req4->l4);
			bibentry_put(bib);
			return -ESRCH;
		}
	}

	/* Remove the fake user. */
	if (bib->is_static) {
		bibentry_put(bib);
		bib->is_static = false;
	}

	/* Remove bib's sessions and their references. */
	error = sessiondb_delete_by_bib(jool->nat64.session, bib);
	if (error) {
		bibentry_put(bib);
		return error;
	}

	/* Remove our own reference. */
	bibentry_put(bib);
	return 0;
}

int handle_bib_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	struct request_bib *request = (struct request_bib *)(jool_hdr + 1);
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have BIBs.");
		return nl_core_respond_error(info, COMMAND, -EINVAL);
	}

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

	return nlcore_respond(info, COMMAND, error);
}
