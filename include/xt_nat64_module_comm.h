#ifndef _XT_NAT64_MODULE_COMM_H
#define _XT_NAT64_MODULE_COMM_H

/**
 * @file 	xt_nat64_module_comm.h
 *
 * @brief 	Contains function used to handle the communication between module
 * 			and user space app.
 *
 * Example from: http://stackoverflow.com/questions/862964/who-can-give-me-the-latest-netlink-programming-samples
 */


#include "nf_nat64_types.h"

//#define MSG_TYPE_CONF (0x10 + 2)  ///< Netlink socket packet ID, configuration
//#define MSG_TYPE_ROUTE (0x10 + 3)  ///< Netlink socket packet ID, static routes 
#define MSG_TYPE_NAT64 (0x10 + 2)  ///< Netlink socket packet ID, configuration

/**
 * A BIB entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct bib_entry" and only used when BIBs need to travel to
 * userspace. For anything else, use "struct bib_entry" from *_bib.h.
 *
 * See *_bib.h for the fields' doc.
 */
struct bib_entry_us
{
	struct ipv4_tuple_address ipv4;
	struct ipv6_tuple_address ipv6;
};

/**
 * A session entry, from the eyes of userspace ("us" stands for userspace).
 *
 * It's a stripped version of "struct session_entry" and only used when sessions need to travel to
 * userspace. For anything else, use "struct session_entry" from *_session.h.
 *
 * See *_session.h for the fields' doc.
 */
struct session_entry_us
{
	struct ipv6_pair ipv6;
	struct ipv4_pair ipv4;
	bool is_static;
	unsigned int dying_time;
	u_int8_t l4protocol;
};


#endif
