/*
 * nl_sender.h
 *
 *  Created on: Oct 15, 2015
 *      Author: dhernandez
 */

#ifndef INCLUDE_NAT64_MOD_COMMON_NL_NL_SENDER_H_
#define INCLUDE_NAT64_MOD_COMMON_NL_NL_SENDER_H_

int nl_sender_init(int sender_sock_family, int sender_sock_group);
struct sock *nl_sender_get(void);

#endif /* INCLUDE_NAT64_MOD_COMMON_NL_NL_SENDER_H_ */
