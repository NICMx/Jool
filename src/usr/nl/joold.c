#include "usr/nl/joold.h"

#include <stddef.h>
#include <netlink/msg.h>
#include "common/config.h"

struct jool_result joolnl_joold_add(struct joolnl_socket *sk, char const *iname,
		void const *data, size_t data_len)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JOP_JOOLD_ADD, 0, &msg);
	if (result.error)
		return result;

	result.error = nla_put(msg, RA_SESSION_ENTRIES, data_len, data);
	if (result.error < 0) {
		nlmsg_free(msg);
		/*
		 * This is fine as long as page size > 1500.
		 * But admittedly, it's not the most elegant implementation.
		 */
		return result_from_error(
			result.error,
			"Can't send joold sessions to kernel: Packet too small."
		);
	}

	return joolnl_request(sk, msg, NULL, NULL);
}

struct jool_result joolnl_joold_advertise(struct joolnl_socket *sk,
		char const *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JOP_JOOLD_ADVERTISE, 0, &msg);
	if (result.error)
		return result;

	return joolnl_request(sk, msg, NULL, NULL);
}

struct jool_result joolnl_joold_ack(struct joolnl_socket *sk, char const *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JOP_JOOLD_ACK, 0, &msg);
	if (result.error)
		return result;

	return joolnl_request(sk, msg, NULL, NULL);
}
