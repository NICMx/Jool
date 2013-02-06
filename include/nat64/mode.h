#ifndef _MODE_H_
#define _MODE_H_

#include <argp.h>
#include "nat64/config_proto.h"


error_t pool6_display(void);
error_t pool6_add(struct ipv6_prefix *prefix);
error_t pool6_remove(struct ipv6_prefix *prefix);

error_t pool4_display(void);
error_t pool4_add(struct in_addr *addr);
error_t pool4_remove(struct in_addr *addr);

error_t bib_display(bool use_tcp, bool use_udp, bool use_icmp);

error_t session_display(bool use_tcp, bool use_udp, bool use_icmp);
error_t session_add(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6,
		struct ipv4_pair *pair4);
error_t session_remove_ipv4(bool use_tcp, bool use_udp, bool use_icmp, struct ipv4_pair *pair4);
error_t session_remove_ipv6(bool use_tcp, bool use_udp, bool use_icmp, struct ipv6_pair *pair6);

error_t filtering_request(__u32 operation, struct filtering_config *config);
error_t translate_request(__u32 operation, struct translate_config *config);

void print_code_msg(struct response_hdr *hdr, const char *mode, const char *success_msg);


#endif /* _MODE_H_ */
