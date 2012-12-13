/**
 * @file 	xt_nat64_module_comm.h
 *
 * @brief 	Contains function used to handle the communication between module
 * 			and user space app.
 *
 */
//~ #ifdef _KERNEL_SPACE
//~ #ifndef _LOAD_CONFIG_H_
#ifndef _USER_SPACE_
	#include <net/sock.h>
	#include <net/netlink.h>
#endif

//#define MSG_TYPE_CONF (0x10 + 2)  ///< Netlink socket packet ID, configuration
//#define MSG_TYPE_ROUTE (0x10 + 3)  ///< Netlink socket packet ID, static routes 

#define MSG_TYPE_NAT64 (0x10 + 2)  ///< Netlink socket packet ID, configuration

/* Testing communication with the module using netlink. Rob
 * Example from: http://stackoverflow.com/questions/862964/who-can-give-me-the-latest-netlink-programming-samples
 */
