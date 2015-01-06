#ifndef _JOOL_USR_POOL4_H
#define _JOOL_USR_POOL4_H

#include <stdbool.h>
#include <arpa/inet.h>


int pool4_display(void);
int pool4_count(void);
int pool4_add(struct in_addr *addr, unsigned char *mask);
int pool4_remove(struct in_addr *addr, unsigned char *mask, bool quick);
int pool4_flush(bool quick);


#endif /* _JOOL_USR_POOL4_H */
