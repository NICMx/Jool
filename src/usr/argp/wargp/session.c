#include "usr/argp/wargp/session.h"

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include "common/config.h"
#include "common/constants.h"
#include "common/session.h"
#include "usr/util/str_utils.h"
#include "usr/nl/core.h"
#include "usr/nl/session.h"
#include "usr/argp/dns.h"
#include "usr/argp/log.h"
#include "usr/argp/userspace-types.h"
#include "usr/argp/wargp.h"
#include "usr/argp/xlator_type.h"

struct display_args {
	struct wargp_bool no_headers;
	struct wargp_bool csv;
	struct wargp_bool numeric;
	struct wargp_l4proto proto;
};

static struct wargp_option display_opts[] = {
	WARGP_TCP(struct display_args, proto, "Print the TCP table (default)"),
	WARGP_UDP(struct display_args, proto, "Print the UDP table"),
	WARGP_ICMP(struct display_args, proto, "Print the ICMP table"),
	WARGP_NO_HEADERS(struct display_args, no_headers),
	WARGP_CSV(struct display_args, csv),
	WARGP_NUMERIC(struct display_args, numeric),
	{ 0 },
};

static char *tcp_state_to_string(tcp_state state)
{
	switch (state) {
	case ESTABLISHED:
		return "ESTABLISHED";
	case V4_INIT:
		return "V4_INIT";
	case V6_INIT:
		return "V6_INIT";
	case V4_FIN_RCV:
		return "V4_FIN_RCV";
	case V6_FIN_RCV:
		return "V6_FIN_RCV";
	case V4_FIN_V6_FIN_RCV:
		return "V4_FIN_V6_FIN_RCV";
	case TRANS:
		return "TRANS";
	}

	return "UNKNOWN";
}

static struct jool_result handle_display_response(
		struct session_entry_usr const *entry, void *args)
{
	struct display_args *dargs = args;
	l4_protocol proto = dargs->proto.proto;
	char timeout[TIMEOUT_BUFLEN];

	timeout2str(entry->dying_time, timeout);

	if (dargs->csv.value) {
		printf("%s,", l4proto_to_string(proto));
		print_addr6(&entry->src6, dargs->numeric.value, ",", proto);
		printf(",");
		print_addr6(&entry->dst6, true, ",", proto);
		printf(",");
		print_addr4(&entry->src4, true, ",", proto);
		printf(",");
		print_addr4(&entry->dst4, dargs->numeric.value, ",", proto);
		printf(",");
		printf("%s", timeout);
		if (proto == L4PROTO_TCP)
			printf(",%s", tcp_state_to_string(entry->state));
		printf("\n");
	} else {
		if (proto == L4PROTO_TCP)
			printf("(%s) ", tcp_state_to_string(entry->state));

		printf("Expires in %s\n", timeout);

		printf("Remote: ");
		print_addr4(&entry->dst4, dargs->numeric.value, "#", proto);
		printf("\t");
		print_addr6(&entry->src6, dargs->numeric.value, "#", proto);
		printf("\n");

		printf("Local: ");
		print_addr4(&entry->src4, true, "#", proto);
		printf("\t");
		print_addr6(&entry->dst6, true, "#", proto);
		printf("\n");

		printf("---------------------------------\n");
	}

	return result_success();
}

int handle_session_display(char *iname, int argc, char **argv, void const *arg)
{
	struct display_args dargs = { 0 };
	struct joolnl_socket sk;
	struct jool_result result;

	result.error = wargp_parse(display_opts, argc, argv, &dargs);
	if (result.error)
		return result.error;

	result = joolnl_setup(&sk, xt_get());
	if (result.error)
		return pr_result(&result);

	if (!dargs.csv.value) {
		printf("---------------------------------\n");
	} else if (show_csv_header(dargs.no_headers.value, dargs.csv.value)) {
		printf("Protocol,");
		printf("IPv6 Remote Address,IPv6 Remote L4-ID,");
		printf("IPv6 Local Address,IPv6 Local L4-ID,");
		printf("IPv4 Local Address,IPv4 Local L4-ID,");
		printf("IPv4 Remote Address,IPv4 Remote L4-ID,");
		printf("Expires in,State\n");
	}

	result = joolnl_session_foreach(&sk, iname, dargs.proto.proto,
			handle_display_response, &dargs);

	joolnl_teardown(&sk);

	return pr_result(&result);
}

/******************************************************************************/

#define SERIALIZED_SESSION_SIZE (		\
		2 * sizeof(struct in6_addr)	\
		+ sizeof(struct in_addr)	\
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
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	l4_protocol proto;
	tcp_state state;
	session_timer_type timer_type;
	unsigned long expiration;
};

struct follow_args {
	struct joolnl_socket jsk;
	char const *iname;
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
		pr_err("Invalid request: Session size (%u) < %zu\n",
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

static void do_ack(struct follow_args *args)
{
	struct nl_msg *msg;
	struct jool_result result;
	int error;

	result = joolnl_alloc_msg(&args->jsk, args->iname, JNLOP_JOOLD_ACK, 0, &msg);
	if (result.error) {
		pr_result(&result);
		return;
	}

	error = nl_send_auto(args->jsk.sk, msg);
	if (error < 0)
		pr_err("Could not dispatch the ACK to kernelspace: %s\n",
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
	struct follow_args *args = arg;
	struct nlmsghdr *nhdr;
	struct genlmsghdr *ghdr;
	struct joolnlhdr *jhdr;
	struct nlattr *root;
	struct jool_result result;

	nhdr = nlmsg_hdr(msg);
	if (!genlmsg_valid_hdr(nhdr, sizeof(struct joolnlhdr))) {
		pr_err("Kernel sent invalid data: Message too short to contain headers\n");
		goto einval;
	}

	ghdr = genlmsg_hdr(nhdr);

	jhdr = genlmsg_user_hdr(ghdr);
	result = validate_joolnlhdr(jhdr, XT_NAT64);
	if (result.error) {
		pr_result(&result);
		goto fail;
	}
	if (strcasecmp(jhdr->iname, args->iname) != 0)
		return 0; /* Packet not intended for us. */
	if (jhdr->flags & JOOLNLHDR_FLAGS_ERROR) {
		result = joolnl_msg2result(msg);
		pr_result(&result);
		goto fail;
	}

	root = genlmsg_attrdata(ghdr, sizeof(struct joolnlhdr));
	if (nla_type(root) != JNLAR_SESSION_ENTRIES) {
		pr_err("Kernel sent invalid data: Message lacks a session container\n");
		goto einval;
	}

	print_sessions(root);

	do_ack(args);
	return 0;

einval:
	result.error = -EINVAL;
fail:
	do_ack(args); /* Tell kernel to flush the packet queue anyway. */
	return (result.error < 0) ? result.error : -result.error;
}

static int create_follow_socket(struct follow_args *args)
{
	int family_mc_grp;
	struct jool_result result;

	result = joolnl_setup(&args->jsk, xt_get());
	if (result.error)
		return pr_result(&result);

	result.error = nl_socket_modify_cb(args->jsk.sk, NL_CB_VALID,
			NL_CB_CUSTOM, print_entries_cb, args);
	if (result.error) {
		pr_err("Couldn't modify receiver socket's callbacks.\n");
		goto fail;
	}

	family_mc_grp = genl_ctrl_resolve_grp(args->jsk.sk, JOOLNL_FAMILY,
			JOOLNL_MULTICAST_GRP_NAME);
	if (family_mc_grp < 0) {
		pr_err("Unable to resolve the Netlink multicast group.\n");
		result.error = family_mc_grp;
		goto fail;
	}

	result.error = nl_socket_add_membership(args->jsk.sk, family_mc_grp);
	if (result.error) {
		pr_err("Can't register to the Netlink multicast group.\n");
		goto fail;
	}

	return 0;

fail:	joolnl_teardown(&args->jsk);
	fprintf(stderr, "Netlink error message: %s\n", nl_geterror(result.error));
	return result.error;
}

int handle_session_follow(char *iname, int argc, char **argv, void const *arg)
{
	struct follow_args args;
	int error;

	args.iname = (iname != NULL) ? iname : "default";

	error = wargp_parse(NULL, argc, argv, NULL);
	if (error)
		return error;

	error = create_follow_socket(&args);
	if (error)
		return error;

	do {
		error = nl_recvmsgs_default(args.jsk.sk);
		if (error < 0)
			pr_err("Trouble receiving packet from kernelspace: %s\n",
					nl_geterror(error));
	} while (true);

	joolnl_teardown(&args.jsk);
	return 0;
}

void autocomplete_session_display(void const *args)
{
	print_wargp_opts(display_opts);
}

void autocomplete_session_follow(void const *args)
{
	/* Nothing needed here. */
}
