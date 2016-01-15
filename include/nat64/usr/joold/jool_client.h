#ifndef JOOL_CLIENT_H
#define JOOL_CLIENT_H

#include <linux/types.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/object.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


#if !defined(LIBNL_VER_NUM)
	#error "Missing LIBNL dependency (need at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3,0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif

	int set_updated_entries(void *data);
	int get_updated_entries(void);
	int jool_client_init(int (*cb)(void *, __u16 size));

#endif
