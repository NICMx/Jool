#include "usr/nl/bib.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"

struct foreach_args {
	bib_foreach_cb cb;
	void *args;
	bool done;
	struct bib_entry last;
};

static struct jool_result attr2entry(struct nlattr *attr,
		struct bib_entry *entry)
{
	struct nlattr *attrs[BA_COUNT];
	struct jool_result result;

	if (nla_type(attr) != LA_ENTRY)
		return result_success(); /* dunno; skip I guess */
	result = jnla_parse_nested(attrs, BA_MAX, attr, bib_entry_policy);
	if (result.error)
		return result;

	result = nla_get_taddr6(attrs[BA_SRC6], &entry->addr6);
	if (result.error)
		return result;
	result = nla_get_taddr4(attrs[BA_SRC4], &entry->addr4);
	if (result.error)
		return result;
	entry->l4_proto = nla_get_u8(attrs[BA_PROTO]);
	entry->is_static = nla_get_u8(attrs[BA_STATIC]);
	return result_success();
}

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args;
	struct genlmsghdr *ghdr;
	struct joolnl_hdr *jhdr;
	struct nlattr *attr;
	int rem;
	struct bib_entry entry;
	struct jool_result result;

	args = arg;
	ghdr = genlmsg_hdr(nlmsg_hdr(response));

	foreach_entry(attr, ghdr, rem) {
		result = attr2entry(attr, &entry);
		if (result.error)
			return result;

		result = args->cb(&entry, args->args);
		if (result.error)
			return result;

		memcpy(&args->last, &entry, sizeof(entry));
	}

	jhdr = genlmsg_user_hdr(ghdr);
	args->done = !(jhdr->flags & HDRFLAGS_M);
	return result_success();
}

struct jool_result bib_foreach(struct jool_socket *sk, char *iname,
	l4_protocol proto, bib_foreach_cb cb, void *_args)
{
	struct nl_msg *msg;
	struct foreach_args args;
	struct jool_result result;
	bool first_request;

	args.cb = cb;
	args.args = _args;
	args.done = false;
	memset(&args.last, 0, sizeof(args.last));
	first_request = true;

	do {
		result = allocate_jool_nlmsg(sk, iname, JOP_BIB_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			if (nla_put_u8(msg, RA_PROTO, proto)) {
				nlmsg_free(msg);
				return packet_too_small();
			}
			first_request = false;
		} else {
			result = nla_put_bib(msg, RA_OFFSET, &args.last);
			if (result.error) {
				nlmsg_free(msg);
				return result;
			}
		}

		result = netlink_request(sk, msg, handle_foreach_response, &args);
		if (result.error)
			return result;
	} while (!args.done);

	return result_success();
}

static struct jool_result __update(struct jool_socket *sk, char *iname,
		enum jool_operation op,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, op, 0, &msg);
	if (result.error)
		return result;

	result = nla_put_bib_attrs(msg, RA_OPERAND, a6, a4, proto, true);
	if (result.error) {
		nlmsg_free(msg);
		return result;
	}

	return netlink_request(sk, msg, NULL, NULL);
}


struct jool_result bib_add(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	return __update(sk, iname, JOP_BIB_ADD, a6, a4, proto);
}

struct jool_result bib_rm(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	return __update(sk, iname, JOP_BIB_RM, a6, a4, proto);
}
