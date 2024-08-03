#ifndef SRC_USR_JOOLD_JSON_H_
#define SRC_USR_JOOLD_JSON_H_

#include "usr/util/cJSON.h"

int read_json(char const *, cJSON **);

int json2str(char const *, cJSON *, char const *, char **);
int json2int(char const *, cJSON *, char const *, int *);

#endif /* SRC_USR_JOOLD_JSON_H_ */
