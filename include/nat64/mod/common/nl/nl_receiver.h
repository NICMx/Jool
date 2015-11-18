/*
 * nl_receiver.h
 *
 *  Created on: Oct 15, 2015
 *      Author: dhernandez
 */

#ifndef INCLUDE_NAT64_MOD_COMMON_NL_NL_RECEIVER_H_
#define INCLUDE_NAT64_MOD_COMMON_NL_NL_RECEIVER_H_

#include <linux/skbuff.h>


int nl_receiver_init(int receiver_sock_family, void (*callback)(struct sk_buff *skb));
struct sock *nl_receiver_get(void);

#endif /* INCLUDE_NAT64_MOD_COMMON_NL_NL_RECEIVER_H_ */
