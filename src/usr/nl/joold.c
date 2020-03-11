#include "usr/nl/joold.h"

#include <stddef.h>
#include <netlink/msg.h>
#include "common/config.h"

struct jool_result joold_add(struct jool_socket *sk, char *iname,
		void *data, size_t data_len)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_JOOLD_ADD, 0, &msg);
	if (result.error)
		return result;

	result.error = nla_put(msg, RA_SESSION_ENTRIES, data_len, data);
	if (result.error) {
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

	return netlink_request(sk, msg, NULL, NULL);
}

struct jool_result joold_advertise(struct jool_socket *sk, char *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_JOOLD_ADVERTISE, 0, &msg);
	if (result.error)
		return result;

	return netlink_request(sk, msg, NULL, NULL);
}

struct jool_result joold_ack(struct jool_socket *sk, char *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_JOOLD_ACK, 0, &msg);
	if (result.error)
		return result;

	return netlink_request(sk, msg, NULL, NULL);
}
