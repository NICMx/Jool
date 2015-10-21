#include <linux/netlink.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include "nat64/mod/common/nl/nl_core.h"

static struct sock *nl_socket = NULL;


int nl_receiver_init(int receiver_sock_family, void (*callback)(struct sk_buff *skb))
{
	nl_socket = nl_create_socket(receiver_sock_family,0,callback) ;

	if (!nl_socket)
		return -1;

	return 0;

}

struct sock *nl_receiver_get(void)
{
	return nl_socket;
}
