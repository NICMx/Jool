#include "eamt.h"

#include "netlink.h"
#include "netlink/nl-attr.h"

struct foreach_args {
	eamt_foreach_cb cb;
	void *args;
};

static int build_foreach_request(struct nl_msg **request, char *instance,
		struct foreach_args *fargs)
{
	struct nl_msg *msg;
	int error;

	error = jnl_create_request(instance, JGNC_EAMT_FOREACH, &msg);
	if (error)
		return error;

	*request = msg;
	return 0;
}

static int handle_foreach_response(struct nl_msg *msg, void *args)
{
	struct nlattr *attr, *subattr;
	int rem, subrem;
	struct foreach_args *fargs = args;
	struct eamt_entry entry;
	int error;

	jnla_foreach_attr(attr, msg, rem) {
		if (attr->nla_type != JNLA_EAM) {
			log_err("Response from kernel contains something that's not an EAMT entry.");
			log_err("Type is %u. Skipping...", attr->nla_type);
			continue;
		}

		subattr = jnla_nested_first(attr, &subrem);
		if (jnla_get_addr6(subattr, JNLA_PREFIX6ADDR, &entry.prefix6.addr))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_u8(subattr, JNLA_PREFIX6LEN, &entry.prefix6.len))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr4(subattr, JNLA_PREFIX4ADDR, &entry.prefix4.addr))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_u8(subattr, JNLA_PREFIX4LEN, &entry.prefix4.len))
			continue;

		error = fargs->cb(&entry, fargs->args);
		if (error)
			return error;
	}

	/* TODO pending data */
	return 0;
}

int eamt_foreach(char *instance, eamt_foreach_cb cb, void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args fargs;
	struct nl_msg *request;
	int error;

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	fargs.cb = cb;
	fargs.args = args;

	do {
		error = build_foreach_request(&request, instance, &fargs);
		if (error)
			break;

		error = jnl_request(&jsocket, request, handle_foreach_response,
				&fargs);

	} while (0);

	jnl_destroy_socket(&jsocket);
	return error;
}

int eamt_add(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		bool force)
{
	struct nl_msg *request;
	int error;

	if (!p6 || !p4) {
		log_err("Both prefixes are mandatory arguments for EAMT add.");
		return -EINVAL;
	}

	error = jnl_create_request(instance, JGNC_EAMT_ADD, &request);
	if (error)
		return error;

	error = jnla_put_prefix6(request, p6)
			|| jnla_put_prefix4(request, p4)
			|| jnla_put_bool(request, JNLA_FORCE, force);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int eamt_rm(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4)
{
	struct nl_msg *request;
	int error;

	if (!p6 && !p4) {
		log_err("Bug: eamt_rm() requires at least one prefix, none given.");
		return -EINVAL;
	}

	error = jnl_create_request(instance, JGNC_EAMT_RM, &request);
	if (error)
		return error;

	error = (p6 && jnla_put_prefix6(request, p6))
			|| (p4 && jnla_put_prefix4(request, p4));
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int eamt_flush(char *instance)
{
	struct nl_msg *request;
	int error;

	error = jnl_create_request(instance, JGNC_EAMT_FLUSH, &request);
	if (error)
		return error;

	return jnl_single_request(request);
}
