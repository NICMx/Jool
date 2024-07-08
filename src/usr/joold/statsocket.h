#ifndef SRC_USR_JOOLD_STATSOCKET_H_
#define SRC_USR_JOOLD_STATSOCKET_H_

#include <stdbool.h>

extern struct statsocket_cfg {
	bool enabled;
	char *address;
	char *port;
} statcfg;

int statsocket_config(char const *);
int statsocket_start(void);

#endif /* SRC_USR_JOOLD_STATSOCKET_H_ */
