#include "usr/argp/joold/modsocket.h"

#include <errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <syslog.h>

#include "common/session.h"
#include "usr/nl/joold.h"
#include "usr/argp/joold/netsocket.h"
#include "usr/argp/log.h"
#include "usr/util/str_utils.h"
#include "usr/joold/log.h"

static char const *iname;

static struct joolnl_socket jsocket;

atomic_int modsocket_pkts_sent;
atomic_int modsocket_bytes_sent;

/* Called by the net socket whenever joold receives data from the network. */
void modsocket_send(void *request, size_t request_len)
{
	struct jool_result result;
	result = joolnl_joold_add(&jsocket, iname, request, request_len);
	pr_result_syslog(&result);
}

#define SERIALIZED_SESSION_SIZE (		\
		sizeof(struct in6_addr)		\
		+ 2 * sizeof(struct in_addr)	\
		+ sizeof(__be32)		\
		+ 4 * sizeof(__be16)		\
)

typedef enum session_timer_type {
	SESSION_TIMER_EST,
	SESSION_TIMER_TRANS,
	SESSION_TIMER_SYN4,
} session_timer_type;

struct session_entry {
	struct ipv6_transport_addr src6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	l4_protocol proto;
	tcp_state state;
	session_timer_type timer_type;
	unsigned long expiration;
};

#define READ_RAW(serialized, field)					\
	memcpy(&field, serialized, sizeof(field));			\
	serialized += sizeof(field);

static int jnla_get_session_joold(struct nlattr *attr,
		struct session_entry *entry)
{
	__u8 *serialized;
	__be32 tmp32;
	__be16 tmp16;
	__u16 __tmp16;

	if (attr->nla_len < SERIALIZED_SESSION_SIZE) {
		syslog(LOG_ERR, "Invalid request: Session size (%u) < %zu\n",
				attr->nla_len, SERIALIZED_SESSION_SIZE);
		return -EINVAL;
	}

	memset(entry, 0, sizeof(*entry));
	serialized = nla_data(attr);

	READ_RAW(serialized, entry->src6.l3);
	READ_RAW(serialized, entry->src4.l3);
	READ_RAW(serialized, entry->dst4.l3);
	READ_RAW(serialized, tmp32);

	READ_RAW(serialized, tmp16);
	entry->src6.l4 = ntohs(tmp16);
	READ_RAW(serialized, tmp16);
	entry->src4.l4 = ntohs(tmp16);
	READ_RAW(serialized, tmp16);
	entry->dst4.l4 = ntohs(tmp16);

	READ_RAW(serialized, tmp16);
	__tmp16 = ntohs(tmp16);
	entry->proto = (__tmp16 >> 5) & 3;
	entry->state = (__tmp16 >> 2) & 7;
	entry->timer_type = __tmp16 & 3;

	entry->expiration = ntohl(tmp32);

	return 0;
}

static void print_sessions(struct nlattr *root)
{
	struct nlattr *attr;
	int rem;
	struct session_entry session;
	char buffer[INET6_ADDRSTRLEN];

	nla_for_each_nested(attr, root, rem) {
		if (jnla_get_session_joold(attr, &session) != 0)
			return;

		printf("%s,", l4proto_to_string(session.proto));
		inet_ntop(AF_INET6, &session.src6.l3, buffer, sizeof(buffer));
		printf("%s,%u,", buffer, session.src6.l4);
		inet_ntop(AF_INET, &session.src4.l3, buffer, sizeof(buffer));
		printf("%s,%u,", buffer, session.src4.l4);
		inet_ntop(AF_INET, &session.dst4.l3, buffer, sizeof(buffer));
		printf("%s,%u,", buffer, session.dst4.l4);
		timeout2str(session.expiration, buffer);
		printf("%s\n", buffer);
	}
}

static void do_ack(void)
{
	struct jool_result result;

	result = joolnl_joold_ack(&jsocket, iname);
	if (result.error)
		pr_result_syslog(&result);
}

/**
 * Called when joold receives data from kernelspace.
 * This data can be either sessions that should be multicasted to other joolds
 * or a response to something sent by modsocket_send().
 */
static int updated_entries_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nhdr;
	struct genlmsghdr *ghdr;
	struct joolnlhdr *jhdr;
	struct nlattr *root;
	struct jool_result result;

	SYSLOG_DBG("Received a packet from kernelspace.");

	nhdr = nlmsg_hdr(msg);
	if (!genlmsg_valid_hdr(nhdr, sizeof(struct joolnlhdr))) {
		syslog(LOG_ERR, "Kernel sent invalid data: Message too short to contain headers");
		goto einval;
	}

	ghdr = genlmsg_hdr(nhdr);

	jhdr = genlmsg_user_hdr(ghdr);
	result = validate_joolnlhdr(jhdr, XT_NAT64);
	if (result.error) {
		pr_result_syslog(&result);
		goto fail;
	}
	if (strcasecmp(jhdr->iname, iname) != 0) {
		SYSLOG_DBG("%s: Packet is intended for %s, not me.",
				iname, jhdr->iname);
		return 0;
	}
	if (jhdr->flags & JOOLNLHDR_FLAGS_ERROR) {
		result = joolnl_msg2result(msg);
		pr_result_syslog(&result);
		goto fail;
	}

	root = genlmsg_attrdata(ghdr, sizeof(struct joolnlhdr));
	if (nla_type(root) != JNLAR_SESSION_ENTRIES) {
		syslog(LOG_ERR, "Kernel sent invalid data: Message lacks a session container");
		goto einval;
	}

	if (netsocket_enabled()) {
		/*
		 * Why do we detach the session container?
		 * Because the Netlink API forces the other end to recreate it.
		 * (See modsocket_send())
		 */
		netsocket_send(nla_data(root), nla_len(root));
		modsocket_pkts_sent++;
		modsocket_bytes_sent += nla_len(root);
	} else {
		print_sessions(root);
	}

	do_ack();
	return 0;

einval:
	result.error = -EINVAL;
fail:
	do_ack(); /* Tell kernel to flush the packet queue anyway. */
	return (result.error < 0) ? result.error : -result.error;
}

int modsocket_setup(char const *instance)
{
	int family_mc_grp;
	struct jool_result result;

	iname = instance ? instance : "default";
	syslog(LOG_INFO, "Opening kernel socket (Instance name: %s)...", iname);

	result = joolnl_setup(&jsocket, XT_NAT64);
	if (result.error)
		return pr_result_syslog(&result);

	result.error = nl_socket_modify_cb(jsocket.sk, NL_CB_VALID,
			NL_CB_CUSTOM, updated_entries_cb, NULL);
	if (result.error) {
		syslog(LOG_ERR, "Couldn't modify receiver socket's callbacks.");
		goto fail;
	}

	family_mc_grp = genl_ctrl_resolve_grp(jsocket.sk, JOOLNL_FAMILY,
			JOOLNL_MULTICAST_GRP_NAME);
	if (family_mc_grp < 0) {
		syslog(LOG_ERR, "Unable to resolve the Netlink multicast group.");
		result.error = family_mc_grp;
		goto fail;
	}

	result.error = nl_socket_add_membership(jsocket.sk, family_mc_grp);
	if (result.error) {
		syslog(LOG_ERR, "Can't register to the Netlink multicast group.");
		goto fail;
	}

	syslog(LOG_INFO, "Kernel socket ready.");
	return 0;

fail:
	joolnl_teardown(&jsocket);
	syslog(LOG_ERR, "Netlink error message: %s", nl_geterror(result.error));
	return result.error;
}

void *modsocket_listen(void *arg)
{
	int error;

	do {
		error = nl_recvmsgs_default(jsocket.sk);
		if (error < 0) {
			syslog(LOG_ERR, "Error receiving packet from kernelspace: %s",
					nl_geterror(error));
		}
	} while (true);

	return 0;
}
