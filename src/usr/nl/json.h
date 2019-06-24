#ifndef SRC_USR_NL_JSON_H_
#define SRC_USR_NL_JSON_H_

#include "jool_socket.h"

struct jool_result parse_file(struct jool_socket *sk, char *iname,
		char *fileName, bool force);

#endif /* SRC_USR_NL_JSON_H_ */
