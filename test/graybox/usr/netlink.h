#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <netlink/msg.h>

int nlsocket_init(char *family);
void nlsocket_destroy();

int nlsocket_create_msg(int cmd, struct nl_msg **msg);
int nlsocket_send(struct nl_msg *msg);

int netlink_print_error(int error);

#endif
