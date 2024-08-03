#ifndef SRC_USR_ARGP_JOOLD_STATSOCKET_H_
#define SRC_USR_ARGP_JOOLD_STATSOCKET_H_

#include <stdbool.h>

struct statsocket_cfg {
	bool enabled;
	char *address;
	char *port;
};

int statsocket_start(struct statsocket_cfg *);

#endif /* SRC_USR_ARGP_JOOLD_STATSOCKET_H_ */
