#ifndef SRC_USR_NL_JSON_H_
#define SRC_USR_NL_JSON_H_

#include "jool_socket.h"

/* TODO (warning) rename these */

struct jool_result parse_file(struct jool_socket *sk, char *iname,
		char *fileName, bool force);
struct jool_result rm_file(struct jool_socket *sk, char *iname,
		char *file_name);

#endif /* SRC_USR_NL_JSON_H_ */
