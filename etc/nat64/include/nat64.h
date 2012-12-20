#ifndef _NAT64_H_
#define _NAT64_H_


#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

// Assert we compile with libnl version >= 3.0
#if !defined(LIBNL_VER_NUM) 
	#error "You MUST install LIBNL library (at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3,0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif


#endif
