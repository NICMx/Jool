#ifndef SRC_USR_NL_JSON_H_
#define SRC_USR_NL_JSON_H_

#include "common/config.h"
#include "usr/nl/jool_socket.h"

struct jool_result json_parse(struct jool_socket *sk, xlator_type xt,
		char *iname, char *file_name, bool force);
struct jool_result json_get_iname(char *file_name, char **out);

#endif /* SRC_USR_NL_JSON_H_ */
