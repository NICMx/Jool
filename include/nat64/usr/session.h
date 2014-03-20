#ifndef _SESSION_H
#define _SESSION_H

#include <stdbool.h>

struct session_config {
	bool numeric_hostname;
};

int session_display(bool use_tcp, bool use_udp, bool use_icmp);
int session_count(bool use_tcp, bool use_udp, bool use_icmp);


#endif /* _SESSION_H */
