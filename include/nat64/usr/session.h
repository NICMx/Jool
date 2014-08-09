#ifndef _JOOL_USR_SESSION_H
#define _JOOL_USR_SESSION_H

#include <stdbool.h>


int session_display(bool use_tcp, bool use_udp, bool use_icmpm, bool numeric_hostname,
		bool csv_format);
int session_count(bool use_tcp, bool use_udp, bool use_icmp);


#endif /* _JOOL_USR_SESSION_H */
