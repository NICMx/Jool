#include <sys/types.h>
#include <string.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/usr/joold/jool_client.h"

#include "nat64/usr/netlink.h"
#include "nat64/usr/types.h"

//Socket which receives data from kernel.
struct nl_sock *receiver_sk;
//Required to call nl_recv
struct sockaddr_nl sockaddr;

//Socket which sends data to kernel.
struct nl_sock *sender_sk;

//Callback function to pass data that was received from kernel.
static int (*sender_callback)(void *, __u16 size);

int set_updated_entries(void *data) {


	int error = 0;
	struct request_hdr* received_data = (struct request_hdr *) data;
	char * magic = malloc(5);


	if (!magic) {
		log_err("Could not allocate memory for magic string variable!");
		return -1;
	}


	magic[4] = '\0';
	memcpy(magic, received_data, 4);

	if (strcmp(magic, "jool") != 0) {
		log_err("Inconsistent data was received from another Jool instance!");
		return -1;
	}


	free(magic);
	magic = NULL;


	error = netlink_request_simple(data, received_data->length+sizeof(*received_data));

	return error;

}

static int updated_entries_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[__ATTR_MAX + 1];
	struct nlmsghdr *hdr;
	struct request_hdr *joold_data;
	struct nl_core_buffer *buffer;
	int error = 0;

	hdr = nlmsg_hdr(msg);

	error = genlmsg_parse(hdr, 0, attrs, __ATTR_MAX, NULL);

	if (error) {
		fprintf(stderr, "%s (%d)\n", nl_geterror(error), error);
		fprintf(stderr, "genlmsg_parse failed. \n");
		return error;
	}

	if (attrs[1]) {
		buffer = (struct nl_core_buffer *)nla_data(attrs[1]);
	} else {
		fprintf(stderr, "null buffer!\n");
		return 0;
	}


	joold_data = (struct request_hdr *)(buffer+1);


	if (buffer->len > (~(__u16)0)) {
		fprintf(stderr, "The kernel module is sending more bytes than this daemon can send through the netkwork! \n"
						"I am not goin to synchronize this! \n"
						"Reducing the number of sessions to queue through Jool's user-space application, can help to solve this");
	}


	sender_callback(joold_data, buffer->len);

	return 0;
}

int jool_client_sk_receiver_init(int (*cb)(void *, __u16 size)) {

	int error = 0;
	int family_mc_grp = 0;
	receiver_sk = nl_socket_alloc();

	if (!receiver_sk) {
		log_err("Couldn't allocate netlink receiver socket!");
		return -1;
	}

	nl_socket_disable_seq_check(receiver_sk);


	sender_callback = cb;

	error = nl_socket_modify_cb(receiver_sk, NL_CB_VALID, NL_CB_CUSTOM,
			updated_entries_callback, NULL);

	if (error) {
		log_err("Couldn't modify receiver socket's callbacks.");
		goto fail;
	}

	error = genl_connect(receiver_sk);

	if (error) {
		log_err("Couldn't connect the receiver socket to the kernel.");
		log_err(
				"This is likely because Jool isn't active and "
				"therefore it hasn't registered the protocol.");
		goto fail;

	}

	family_mc_grp = genl_ctrl_resolve_grp(receiver_sk, GNL_JOOL_FAMILY_NAME, GNL_JOOLD_MULTICAST_GRP_NAME);


	if (family_mc_grp < 0) {
		log_err("Clouldn't add socket as member of the family and multicast group!");
		goto fail;
	}


	error = nl_socket_add_membership(receiver_sk, family_mc_grp);

	if (error) {
		log_err("Clouldn't add socket as member of the family and multicast group!");
		goto fail;
	}



	return 0;

	fail:
	log_err("%s (error code %d)", nl_geterror(error), error);
	return error;
}

int jool_client_sk_sender_init() {

	sender_sk = nl_socket_alloc();

	if (!sender_sk) {
		log_err("Couldn't allocate netlink sender socket!");
		return -1;
	}

	nl_socket_disable_seq_check(sender_sk);

	return 0;

}

int jool_client_init(int (*cb)(void *, __u16 size)) {

	int error = 0;


	error = netlink_init();

	if (error) {
		return error;
	}


	error = jool_client_sk_receiver_init(cb);

	if (error) {
		return error;
	}



	return 0;
}

int get_updated_entries(void) {
	int error;

	error = nl_recvmsgs_default(receiver_sk);
	printf("error code: %d\n", error);
	if (error < 0)
		printf("error: %s\n", nl_geterror(error));

	return 0;
}

