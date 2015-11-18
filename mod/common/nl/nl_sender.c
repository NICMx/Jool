#include <linux/netlink.h>
#include "nat64/mod/common/nl/nl_core.h"

static struct sock *nl_socket = NULL;

int nl_sender_init(int sender_sock_family, unsigned int sender_sock_group)
{
	nl_socket = nl_create_socket(sender_sock_family, sender_sock_group,NULL);

	if (!nl_socket)
		/* TODO this (instead of callers) should probably be the one who prints the error msg. */
		return -1;


	return 0;
}

struct sock *nl_sender_get(void)
{
	return nl_socket;
}
