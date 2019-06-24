#ifndef SRC_USR_NL_JOOLD_H_
#define SRC_USR_NL_JOOLD_H_

#include "jool_socket.h"

struct jool_result joold_advertise(struct jool_socket *sk, char *iname);
struct jool_result joold_test(struct jool_socket *sk, char *iname);

#endif /* SRC_USR_NL_JOOLD_H_ */
