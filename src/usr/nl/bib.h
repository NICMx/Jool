#ifndef SRC_USR_NL_BIB_H_
#define SRC_USR_NL_BIB_H_

#include "common/config.h"
#include "usr/nl/jool_socket.h"

typedef struct jool_result (*bib_foreach_cb)(struct bib_entry *, void *);

struct jool_result bib_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, bib_foreach_cb cb, void *args);
struct jool_result bib_add(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto);
struct jool_result bib_rm(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto);

#endif /* SRC_USR_NL_BIB_H_ */
