#ifndef _SESSION_H
#define _SESSION_H

#include "nat64/comm/types.h"


int session_display(bool use_tcp, bool use_udp, bool use_icmp);
int session_add(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6,
		struct ipv4_pair *pair4);
int session_remove_ipv4(bool use_tcp, bool use_udp, bool use_icmp, struct ipv4_pair *pair4);
int session_remove_ipv6(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6);


#endif /* _SESSION_H */
