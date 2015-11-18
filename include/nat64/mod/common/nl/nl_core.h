/*
 * core.h
 *
 *  Created on: Oct 15, 2015
 *      Author: dhernandez
 */

#ifndef INCLUDE_NAT64_MOD_COMMON_NL_NL_CORE_H_
#define INCLUDE_NAT64_MOD_COMMON_NL_NL_CORE_H_

struct sock *nl_create_socket(int sock_family, unsigned int sock_group, void (*callback)(struct sk_buff *skb));

#endif /* INCLUDE_NAT64_MOD_COMMON_NL_NL_CORE_H_ */
