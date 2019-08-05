#ifndef SRC_USR_NL_ADDRESS_H_
#define SRC_USR_NL_ADDRESS_H_

#include "common/config.h"
#include "jool_socket.h"

struct jool_result address_query64(struct jool_socket *sk, char *iname,
		struct in6_addr *addr, struct result_addrxlat64 *result);
struct jool_result address_query46(struct jool_socket *sk, char *iname,
		struct in_addr *addr, struct result_addrxlat46 *result);

#endif /* SRC_USR_NL_ADDRESS_H_ */
