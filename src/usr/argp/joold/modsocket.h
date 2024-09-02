#ifndef SRC_USR_ARGP_JOOLD_MODSOCKET_H_
#define SRC_USR_ARGP_JOOLD_MODSOCKET_H_

/* This is the socket we use to talk to the kernel module. */

#include <stddef.h>

int modsocket_setup(char const *iname);

void *modsocket_listen(void *arg);
void modsocket_send(void *buffer, size_t size);

#endif /* SRC_USR_ARGP_JOOLD_MODSOCKET_H_ */
