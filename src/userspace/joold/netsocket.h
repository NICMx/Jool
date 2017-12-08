#ifndef _JOOL_JOOLD_NETSOCKET_H
#define _JOOL_JOOLD_NETSOCKET_H

/**
 * This is the socket we use to talk to other joold instances in the network.
 */

#include <stddef.h>

int netsocket_init(int argc, char **argv);
void netsocket_destroy(void);

void *netsocket_listen(void *arg);
void netsocket_send(void *buffer, size_t size);

#endif
