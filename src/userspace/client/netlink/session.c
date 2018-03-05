#include "session.h"

#include "netlink.h"
#include "netlink/nl-attr.h"

struct foreach_args {
	session_foreach_cb cb;
	void *args;
};

static int build_foreach_request(struct nl_msg **request, char *instance,
		l4_protocol proto, struct foreach_args *fargs)
{
	struct nl_msg *msg;
	int error;

	error = jnl_create_request(instance, JGNC_SESSION_FOREACH, &msg);
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
	struct session_entry_usr entry;
	int error;

	jnla_foreach_attr(attr, msg, rem) {
		if (attr->nla_type != JNLA_SESSION_ENTRY) {
			log_err("Response from kernel contains something that's not a session entry.");
			log_err("Type is %u. Skipping...", attr->nla_type);
			continue;
		}

		subattr = jnla_nested_first(attr, &subrem);
		if (jnla_get_addr6(subattr, JNLA_SADDR6, &entry.src6.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT6, &entry.src6.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr6(subattr, JNLA_DADDR6, &entry.dst6.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_DPORT6, &entry.dst6.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr4(subattr, JNLA_SADDR4, &entry.src4.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_SPORT4, &entry.src4.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_addr4(subattr, JNLA_DADDR4, &entry.dst4.l3))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_port(subattr, JNLA_DPORT4, &entry.dst4.l4))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_l4proto(subattr, &entry.proto))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_u64(subattr, JNLA_DYING_TIME, &entry.dying_time))
			continue;
		subattr = jnla_next(subattr, &subrem);
		if (jnla_get_tcp_state(subattr, &entry.state))
			continue;

		error = fargs->cb(&entry, fargs->args);
		if (error)
			return error;
	}

	/* TODO pending data */
	return 0;
}

int session_foreach(char *instance, l4_protocol proto, session_foreach_cb cb,
		void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args fargs;
	struct nl_msg *request;
	bool error;

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
