#include "nl/nl-bib.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

static int bib_entry_to_userspace(struct bib_entry *entry, bool is_static,
		void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;
	struct bib_entry_usr entry_usr;

	entry_usr.addr4 = entry->ipv4;
	entry_usr.addr6 = entry->ipv6;
	entry_usr.l4_proto = entry->l4_proto;
	entry_usr.is_static = is_static;

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_bib_foreach(struct bib *db, struct genl_info *info,
		struct request_bib_foreach *request)
{
	struct nlcore_buffer buffer;
	struct bib_foreach_func func = {
			.cb = bib_entry_to_userspace,
			.arg = &buffer,
	};
	struct ipv4_transport_addr *offset;
	int error;

	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Sending BIB to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	offset = request->addr4_set ? &request->addr4 : NULL;
	error = bib_foreach(db, request->l4_proto, &func, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_bib_add(struct xlator *jool, struct request_bib_add *request)
{
	struct bib_entry new;
	struct bib_entry old;
	int error;

	if (verify_privileges())
		return -EPERM;

	log_debug("Adding BIB entry.");

	if (!pool4db_contains(jool->pool4, request->l4_proto,
			&request->addr4)) {
		log_err("The transport address '%pI4#%u' does not belong to pool4.\n"
				"Please add it there first.",
				&request->addr4.l3, request->addr4.l4);
		return -EINVAL;
	}

	new.ipv6 = request->addr6;
	new.ipv4 = request->addr4;
	new.l4_proto = request->l4_proto;

	error = bib_add_static(jool->bib, &new, &old);
	switch (error) {
	case 0:
		break;
	case -EEXIST:
		log_err("Entry %pI4#%u|%pI6c#%u collides with %pI4#%u|%pI6c#%u.",
				&new.ipv4.l3, new.ipv4.l4,
				&new.ipv6.l3, new.ipv6.l4,
				&old.ipv4.l3, old.ipv4.l4,
				&old.ipv6.l3, old.ipv6.l4);
		break;
	default:
		log_err("Unknown error code: %d", error);
		break;
	}

	return error;
}

static int handle_bib_rm(struct xlator *jool, struct request_bib_rm *request)
{
	struct bib_entry bib;
	int error;

	if (verify_privileges())
		return -EPERM;

	log_debug("Removing BIB entry.");

	if (request->addr6_set && request->addr4_set) {
		bib.ipv6 = request->addr6;
		bib.ipv4 = request->addr4;
		bib.l4_proto = request->l4_proto;
		error = 0;
	} else if (request->addr6_set) {
		error = bib_find6(jool->bib, request->l4_proto,
				&request->addr6, &bib);
	} else if (request->addr4_set) {
		error = bib_find4(jool->bib, request->l4_proto,
				&request->addr4, &bib);
	} else {
		log_err("You need to provide an address so I can find the entry you want to remove.");
		return -EINVAL;
	}

	if (error == -ESRCH)
		goto esrch;
	if (error)
		return error;

	error = bib_rm(jool->bib, &bib);
	if (error == -ESRCH) {
		if (request->addr6_set && request->addr4_set)
			goto esrch;
		/* It died on its own between the find and the rm. */
		return 0;
	}

	return error;

esrch:
	log_err("The entry wasn't in the database.");
	return -ESRCH;
}

int handle_bib_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	void *payload = get_jool_payload(info);
	int error;

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_bib_foreach(jool->bib, info, payload);
	case OP_ADD:
		error = handle_bib_add(jool, payload);
		break;
	case OP_REMOVE:
		error = handle_bib_rm(jool, payload);
		break;
	default:
		log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
		error = -EINVAL;
	}

	return nlcore_respond(info, error);
}
