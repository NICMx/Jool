#include <errno.h>
#include <stdio.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "common/session.h"
#include "usr/nl/core.h"

#define SERIALIZED_SESSION_SIZE (2 * sizeof(struct in6_addr) \
		+ sizeof(struct in_addr) + sizeof(__be32) + 4 * sizeof(__be16))

typedef enum session_timer_type {
	SESSION_TIMER_EST,
	SESSION_TIMER_TRANS,
	SESSION_TIMER_SYN4,
} session_timer_type;

struct session_entry {
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	l4_protocol proto;
	tcp_state state;
	session_timer_type timer_type;
	unsigned long expiration;
};

static struct joolnl_socket jsocket;
static char *iname;

static int pr_result(struct jool_result *result)
{
	if (result->error)
		fprintf(stderr, "%s\n", result->msg);

	result_cleanup(result);
	return result->error;
}

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
		fprintf(stderr, "Invalid request: Session size (%u) < %zu\n",
				attr->nla_len, SERIALIZED_SESSION_SIZE);
		return -EINVAL;
	}

	memset(entry, 0, sizeof(*entry));
	serialized = nla_data(attr);

	READ_RAW(serialized, entry->src6.l3);
	READ_RAW(serialized, entry->dst6.l3);
	READ_RAW(serialized, entry->src4.l3);
	READ_RAW(serialized, tmp32);

	READ_RAW(serialized, tmp16);
	entry->src6.l4 = ntohs(tmp16);
	READ_RAW(serialized, tmp16);
	entry->dst6.l4 = ntohs(tmp16);
	READ_RAW(serialized, tmp16);
	entry->src4.l4 = ntohs(tmp16);

	READ_RAW(serialized, tmp16);
	__tmp16 = ntohs(tmp16);
	entry->proto = (__tmp16 >> 5) & 3;
	entry->state = (__tmp16 >> 2) & 7;
	entry->timer_type = __tmp16 & 3;

	entry->dst4.l3.s_addr = entry->dst6.l3.s6_addr32[3]; /* XXX wtf? */
	entry->dst4.l4 = (entry->proto == L4PROTO_ICMP)
			? entry->src4.l4
			: entry->dst6.l4;

	entry->expiration = ntohl(tmp32);

	return 0;
}

static void print_sessions(struct nlattr *root)
{
	struct nlattr *attr;
	int rem;
	struct session_entry session;
	char hostaddr[INET6_ADDRSTRLEN];

	nla_for_each_nested(attr, root, rem) {
		if (jnla_get_session_joold(attr, &session) != 0)
			return;

		inet_ntop(AF_INET6, &session.src6.l3, hostaddr, sizeof(hostaddr));
		printf("%s,%u,", hostaddr, session.src6.l4);
		inet_ntop(AF_INET6, &session.dst6.l3, hostaddr, sizeof(hostaddr));
		printf("%s,%u,", hostaddr, session.dst6.l4);
		inet_ntop(AF_INET, &session.src4.l3, hostaddr, sizeof(hostaddr));
		printf("%s,%u,", hostaddr, session.src4.l4);
		inet_ntop(AF_INET, &session.dst4.l3, hostaddr, sizeof(hostaddr));
		printf("%s,%u,", hostaddr, session.dst4.l4);
		printf("%s,", l4proto_to_string(session.proto));
		printf("%lu\n", session.expiration);
	}
}

static void do_ack(void)
{
	struct nl_msg *msg;
	struct jool_result result;
	int error;

	result = joolnl_alloc_msg(&jsocket, iname, JNLOP_JOOLD_ACK, 0, &msg);
	if (result.error) {
		pr_result(&result);
		return;
	}

	error = nl_send_auto(jsocket.sk, msg);
	if (error < 0)
		fprintf(stderr, "Could not dispatch the ACK to kernelspace: %s\n",
				nl_geterror(error));

	nlmsg_free(msg);
}

/**
 * Called when joold receives data from kernelspace.
 * This data can be either sessions that should be multicasted to other joolds
 * or a response to something sent by modsocket_send().
 */
static int print_entries_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nhdr;
	struct genlmsghdr *ghdr;
	struct joolnlhdr *jhdr;
	struct nlattr *root;
	struct jool_result result;

	nhdr = nlmsg_hdr(msg);
	if (!genlmsg_valid_hdr(nhdr, sizeof(struct joolnlhdr))) {
		fprintf(stderr, "Kernel sent invalid data: Message too short to contain headers\n");
		goto einval;
	}

	ghdr = genlmsg_hdr(nhdr);

	jhdr = genlmsg_user_hdr(ghdr);
	result = validate_joolnlhdr(jhdr, XT_NAT64);
	if (result.error) {
		pr_result(&result);
		goto fail;
	}
	if (strcasecmp(jhdr->iname, iname) != 0)
		return 0; /* Packet is not intended for us. */
	if (jhdr->flags & JOOLNLHDR_FLAGS_ERROR) {
		result = joolnl_msg2result(msg);
		pr_result(&result);
		goto fail;
	}

	root = genlmsg_attrdata(ghdr, sizeof(struct joolnlhdr));
	if (nla_type(root) != JNLAR_SESSION_ENTRIES) {
		fprintf(stderr, "Kernel sent invalid data: Message lacks a session container\n");
		goto einval;
	}

	print_sessions(root);

	do_ack();
	return 0;

einval:
	result.error = -EINVAL;
fail:
	do_ack(); /* Tell kernel to flush the packet queue anyway. */
	return (result.error < 0) ? result.error : -result.error;
}

static int create_socket(void)
{
	int family_mc_grp;
	struct jool_result result;

	result = joolnl_setup(&jsocket, XT_NAT64);
	if (result.error)
		return pr_result(&result);

	result.error = nl_socket_modify_cb(jsocket.sk, NL_CB_VALID,
			NL_CB_CUSTOM, print_entries_cb, NULL);
	if (result.error) {
		fprintf(stderr, "Couldn't modify receiver socket's callbacks.\n");
		goto fail;
	}

	family_mc_grp = genl_ctrl_resolve_grp(jsocket.sk, JOOLNL_FAMILY,
			JOOLNL_MULTICAST_GRP_NAME);
	if (family_mc_grp < 0) {
		fprintf(stderr, "Unable to resolve the Netlink multicast group.\n");
		result.error = family_mc_grp;
		goto fail;
	}

	result.error = nl_socket_add_membership(jsocket.sk, family_mc_grp);
	if (result.error) {
		fprintf(stderr, "Can't register to the Netlink multicast group.\n");
		goto fail;
	}

	return 0;

fail:
	joolnl_teardown(&jsocket);
	fprintf(stderr, "Netlink error message: %s\n", nl_geterror(result.error));
	return result.error;
}

int main(int argc, char **argv)
{
	int error;

	iname = (argc < 2) ? "default" : argv[1];

	error = create_socket();
	if (error) {
		fprintf(stderr, "jnetflow error: %d\n", error);
		return error;
	}

	do {
		error = nl_recvmsgs_default(jsocket.sk);
		if (error < 0) {
			fprintf(stderr, "Error receiving packet from kernelspace: %s\n",
					nl_geterror(error));
		}
	} while (true);

	return 0;
}
