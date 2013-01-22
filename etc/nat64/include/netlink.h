#ifndef _NETLINK_H_
#define _NETLINK_H_


#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>


// Assert we're compiling with libnl version >= 3.0
#if !defined(LIBNL_VER_NUM) 
	#error "Missing LIBNL dependency (need at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3,0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif

int netlink_request(void *request, __u16 request_len, int (*callback)(struct nl_msg *, void *));


#endif
