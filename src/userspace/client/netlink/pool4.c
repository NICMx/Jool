#include "pool4.h"

#include "netlink.h"
#include "netlink/nl-attr.h"

struct foreach_args {
	pool4_foreach_cb cb;
	void *args;
};

static int build_foreach_request(struct nl_msg **request, char *instance,
		l4_protocol proto, struct foreach_args *fargs)
{
	struct nl_msg *msg;
	int error;

	error = jnl_create_request(instance, JGNC_POOL4_FOREACH, &msg);
	if (error)
		return error;

	error = jnla_put_l4proto(msg, proto);
	if (error) {
		nlmsg_free(msg);
		return error;
	}

	*request = msg;
	return 0;
}

static int handle_foreach_response(struct nl_msg *msg, void *args)
{
	struct nlattr *attr, *subattr;
	int rem, subrem;
	struct foreach_args *fargs = args;
	struct pool4_sample sample;
	int error;

	jnla_foreach_attr(attr, msg, rem) {
		if (attr->nla_type != JNLA_POOL4_ENTRY) {
			log_err("Response from kernel contains something that's not a pool4 entry.");
			log_err("Type is %u. Skipping...", attr->nla_type);
			continue;
		}

		subattr = jnla_nested_first(attr, &subrem);
		if (jnla_get_u32(subattr, JNLA_MARK, &sample.mark))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_u32(subattr, JNLA_ITERATIONS, &sample.iterations))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_u8(subattr, JNLA_ITERATION_FLAGS, &sample.iteration_flags))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_l4proto(subattr, &sample.proto))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr4(subattr, JNLA_SADDR4, &sample.range.addr))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT4, &sample.range.ports.min))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT4, &sample.range.ports.max))
			continue;

		error = fargs->cb(&sample, fargs->args);
		if (error)
			return error;
	}

	/* TODO pending data */
	return 0;
}

int pool4_foreach(char *instance, l4_protocol proto, pool4_foreach_cb cb,
		void *args)
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
		error = build_foreach_request(&request, instance, proto, &fargs);
		if (error)
			break;

		error = jnl_request(&jsocket, request, handle_foreach_response,
				&fargs);

	} while (0);

	jnl_destroy_socket(&jsocket);
	return error;
}

int pool4_add(char *instance, struct pool4_entry_usr *entry)
{
	struct nl_msg *request;
	int error;

	error = jnl_create_request(instance, JGNC_POOL4_ADD, &request);
	if (error)
		return error;

	error = nla_put_u32(request, JNLA_MARK, entry->mark)
			|| nla_put_u32(request, JNLA_ITERATIONS, entry->iterations)
			|| nla_put_u8(request, JNLA_ITERATION_FLAGS, entry->flags)
			|| jnla_put_l4proto(request, entry->proto)
			|| jnla_put_prefix4(request, &entry->range.prefix)
			|| jnla_put_port(request, JNLA_MINPORT, entry->range.ports.min)
			|| jnla_put_port(request, JNLA_MAXPORT, entry->range.ports.max);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int pool4_rm(char *instance, struct pool4_entry_usr *entry, bool quick)
{
	struct nl_msg *request;
	int error;

	error = jnl_create_request(instance, JGNC_POOL4_RM, &request);
	if (error)
		return error;

	error = nla_put_u32(request, JNLA_MARK, entry->mark)
			|| jnla_put_l4proto(request, entry->proto)
			|| jnla_put_prefix4(request, &entry->range.prefix)
			|| jnla_put_port(request, JNLA_MINPORT, entry->range.ports.min)
			|| jnla_put_port(request, JNLA_MAXPORT, entry->range.ports.max)
			|| jnla_put_bool(request, JNLA_QUICK, quick);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}

int pool4_flush(char *instance, bool quick)
{
	struct nl_msg *request;
	int error;

	error = jnl_create_request(instance, JGNC_POOL4_FLUSH, &request);
	if (error)
		return error;

	error = jnla_put_bool(request, JNLA_QUICK, quick);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	return jnl_single_request(request);
}
