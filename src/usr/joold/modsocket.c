#include "modsocket.h"

#include <errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <syslog.h>

#include "usr/joold/json.h"
#include "usr/joold/log.h"
#include "usr/nl/joold.h"
#include "usr/joold/netsocket.h"

struct modsocket_cfg modcfg;

static struct joolnl_socket jsocket;

atomic_int modsocket_pkts_sent;
atomic_int modsocket_bytes_sent;

/* Called by the net socket whenever joold receives data from the network. */
void modsocket_send(void *request, size_t request_len)
{
	struct jool_result result;
	result = joolnl_joold_add(&jsocket, modcfg.iname, request, request_len);
	pr_result(&result);
}

static void do_ack(void)
{
	struct jool_result result;

	result = joolnl_joold_ack(&jsocket, modcfg.iname);
	if (result.error)
		pr_result(&result);
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

	syslog(LOG_DEBUG, "Received a packet from kernelspace.");

	nhdr = nlmsg_hdr(msg);
	if (!genlmsg_valid_hdr(nhdr, sizeof(struct joolnlhdr))) {
		syslog(LOG_ERR, "Kernel sent invalid data: Message too short to contain headers");
		goto einval;
	}

	ghdr = genlmsg_hdr(nhdr);

	jhdr = genlmsg_user_hdr(ghdr);
	result = validate_joolnlhdr(jhdr, XT_NAT64);
	if (result.error) {
		pr_result(&result);
		goto fail;
	}
	if (strcasecmp(jhdr->iname, modcfg.iname) != 0)
		return 0; /* Packet is not intended for us. */
	if (jhdr->flags & JOOLNLHDR_FLAGS_ERROR) {
		result = joolnl_msg2result(msg);
		pr_result(&result);
		goto fail;
	}

	root = genlmsg_attrdata(ghdr, sizeof(struct joolnlhdr));
	if (nla_type(root) != JNLAR_SESSION_ENTRIES) {
		syslog(LOG_ERR, "Kernel sent invalid data: Message lacks a session container");
		goto einval;
	}

	/*
	 * Why do we detach the session container?
	 * Because the Netlink API forces the other end to recreate it.
	 * (See modsocket_send())
	 */
	netsocket_send(nla_data(root), nla_len(root));
	do_ack();

	modsocket_pkts_sent++;
	modsocket_bytes_sent += nla_len(root);
	return 0;

einval:
	result.error = -EINVAL;
fail:
	do_ack(); /* Tell kernel to flush the packet queue anyway. */
	return (result.error < 0) ? result.error : -result.error;
}

int modsocket_config(char const *filename)
{
	cJSON *json;
	int error;

	error = read_json(filename, &json);
	if (error)
		return error;

	error = json2str(json, "instance", &modcfg.iname);

	cJSON_Delete(json);
	return error;
}

int modsocket_setup(void)
{
	int family_mc_grp;
	struct jool_result result;

	syslog(LOG_INFO, "Opening kernel socket (Instance name: %s)...",
			modcfg.iname);

	result = joolnl_setup(&jsocket, XT_NAT64);
	if (result.error)
		return pr_result(&result);

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
