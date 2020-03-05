#ifndef SRC_USR_NL_GLOBAL_H_
#define SRC_USR_NL_GLOBAL_H_

#include "common/globals.h"
#include "jool_socket.h"


struct jool_result global_query(struct jool_socket *sk, char *iname,
		struct globals *out);

struct jool_result global_update(struct jool_socket *sk, char *iname,
		struct global_field *field, char const *value, bool force);


#endif /* SRC_USR_NL_GLOBAL_H_ */
