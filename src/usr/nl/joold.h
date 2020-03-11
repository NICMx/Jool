#ifndef SRC_USR_NL_JOOLD_H_
#define SRC_USR_NL_JOOLD_H_

#include "usr/nl/jool_socket.h"

struct jool_result joold_add(struct jool_socket *sk, char *iname,
		void *data, size_t data_len);
struct jool_result joold_advertise(struct jool_socket *sk, char *iname);
struct jool_result joold_ack(struct jool_socket *sk, char *iname);

#endif /* SRC_USR_NL_JOOLD_H_ */
