#ifndef SRC_USR_JOOLD_MODSOCKET_H_
#define SRC_USR_JOOLD_MODSOCKET_H_

/* This is the socket we use to talk to the kernel module. */

#include <stddef.h>

extern struct modsocket_cfg {
	char *iname;
} modcfg;

int modsocket_config(char const *filename);
int modsocket_setup(void);

void *modsocket_listen(void *arg);
void modsocket_send(void *buffer, size_t size);

#endif /* SRC_USR_JOOLD_MODSOCKET_H_ */
