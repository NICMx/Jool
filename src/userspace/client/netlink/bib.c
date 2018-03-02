#include "bib.h"

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include "netlink.h"
#include "netlink/nl-attr.h"

struct foreach_args {
	bib_foreach_cb cb;
	void *args;

	bool addr4_set;
	struct ipv4_transport_addr addr4;
};

static int build_foreach_request(struct nl_msg **request, char *instance,
		l4_protocol proto, struct foreach_args *args)
{
	struct nl_msg *msg;
	int error;

	error = jnl_create_request(instance, JGNC_BIB_FOREACH, &msg);
	if (error)
		return error;

	error = jnla_put_proto(msg, proto);
	if (error)
		goto fail;
	if (args->addr4_set) {
		error = jnla_put_src_taddr4(msg, &args->addr4);
		if (error)
			goto fail;
	}

	*request = msg;
	return 0;

fail:
	nlmsg_free(msg);
	return error;
}

static int handle_foreach_response(struct nl_msg *msg, void *args)
{
	struct nlattr *attr, *subattr;
	int rem, subrem;
	struct foreach_args *dargs = args;
	struct bib_entry_usr entry;
	int error;

	/* TODO missing protocol */

	jnla_foreach_attr(attr, msg, rem) {
		if (attr->nla_type != JNLA_BIB_ENTRY) {
			log_err("Response from kernel contains something that's not a BIB entry.");
			log_err("Type is %u. Skipping...", attr->nla_type);
			continue;
		}

		subattr = jnla_nested_first(attr, &subrem);
		if (jnla_get_addr6(subattr, JNLA_SADDR6, &entry.addr6.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT6, &entry.addr6.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr4(subattr, JNLA_SADDR4, &entry.addr4.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT4, &entry.addr4.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_bool(subattr, JNLA_STATIC, &entry.is_static))
			continue;

		error = dargs->cb(&entry, dargs->args);
		if (error)
			return error;
	}

	/* TODO pending data */
	return 0;
}

int bib_foreach(char *instance, l4_protocol proto,
		bib_foreach_cb cb, void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args dargs;
	struct nl_msg *request;
	int error;

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	dargs.cb = cb;
	dargs.args = args;
	dargs.addr4_set = false;
	memset(&dargs.addr4, 0, sizeof(dargs.addr4));

	do {
		error = build_foreach_request(&request, instance, proto, &dargs);
		if (error)
			break;

		error = jnl_request(&jsocket, request, handle_foreach_response,
				&dargs);

	} while (!error && dargs.addr4_set);

	jnl_destroy_socket(&jsocket);
	return error;
}

int bib_add(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	struct nl_msg *request;
	int error;

	error = jnl_create_request(instance, JGNC_BIB_ADD, &request);
	if (error)
		return error;

	error = jnla_put_proto(request, proto)
			|| jnla_put_src_taddr6(request, a6)
			|| jnla_put_src_taddr4(request, a4);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int bib_rm(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	struct nl_msg *request;
	int error;

	if (!a6 && !a4) {
		log_err("Bug: bib_rm() requires at least one transport address, none given.");
		return -EINVAL;
	}

	error = jnl_create_request(instance, JGNC_BIB_RM, &request);
	if (error)
		return error;

	error = jnla_put_proto(request, proto)
			|| (a6 && jnla_put_src_taddr6(request, a6))
			|| (a4 && jnla_put_src_taddr4(request, a4));
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}
