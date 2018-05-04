#ifndef _JOOL_JOOLD_MODSOCKET_H
#define _JOOL_JOOLD_MODSOCKET_H

/**
 * This is the socket we use to talk to the kernel module.
 */

#include <stddef.h>

int modsocket_setup(void);
void modsocket_teardown(void);

void *modsocket_listen(void *arg);
void modsocket_send(void *buffer, size_t size);

#endif
