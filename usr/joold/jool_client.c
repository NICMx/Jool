/*
 * jool_client.c
 *
 *  Created on: Sep 30, 2015
 *      Author: rolivas
 */
#include <sys/types.h>
#include <string.h>
#include "nat64/common/config.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/usr/joold/jool_client.h"
#include "nat64/usr/types.h"

//Socket which receives data from kernel.
struct nl_sock *receiver_sk;
//Required to call nl_recv
struct sockaddr_nl sockaddr;

//Socket which sends data to kernel.
struct nl_sock *sender_sk;

//Callback function to pass data that was received from kernel.
static int (*sender_callback)(void *, size_t size);

void print_received_entries(struct request_hdr *received_data) {
	log_info("received data length: %ul", received_data->length);
}

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

	log_info("received magic is -> %s",magic);
	log_info("received s_element magic -> %s", (received_data+1));

	error = nl_connect(sender_sk, NETLINK_USERSOCK);
	error = nl_send_simple(sender_sk, MSG_TYPE_JOOL, 0, received_data,
			received_data->length);
	if (error < 0) {
		log_err(
				"Could not send the request to Jool (is it really up?).\n" "Netlink error message: %s (Code %d)",
				nl_geterror(error), error);
		goto fail_close;
	}

	error = nl_recvmsgs_default(sender_sk);
	if (error < 0) {
		log_err("%s (System error %d)", nl_geterror(error), error);
		goto fail_close;
	}

	nl_close(sender_sk);

	return 0;

	fail_close:

	nl_close(sender_sk);

	return -1;

}

static int updated_entries_callback(struct nl_msg *msg, void *arg) {
	struct nlmsghdr *hdr;
	struct request_hdr *joold_data;
	__u8 * payload;

	hdr = nlmsg_hdr(msg);
	payload = nlmsg_data(hdr);

	joold_data = (struct request_hdr*) payload;
	char * entry_magic = joold_data;
	entry_magic += sizeof(*joold_data);

	log_info("received header string -> %s", payload/*joold_data->magic*/);
	log_info("entry magic -> %s",entry_magic) ;

	sender_callback(payload, sizeof(struct request_hdr) + joold_data->length);

	return 0;
}

int jool_client_sk_receiver_init(int (*cb)(void *, size_t size)) {

	int error = 0;
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

	error = nl_connect(receiver_sk, 22);

	if (error) {
		log_err("Couldn't connect the receiver socket to the kernel.");
		log_err(
				"This is likely because Jool isn't active and " "therefore it hasn't registered the protocol.");
		goto fail;

	}

	error = nl_socket_add_membership(receiver_sk, JOOLD_MULTICAST_GROUP);

	if (error) {
		log_err("Clouldn't add socket as member of JOOLD_MULTICAST_GROUP");
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

int jool_client_init(int (*cb)(void *, size_t size)) {

	int error = 0;

	error = jool_client_sk_receiver_init(cb);

	if (error) {
		return error;
	}

	error = jool_client_sk_sender_init();

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

