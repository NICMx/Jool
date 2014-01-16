#ifndef _POOL4_H
#define _POOL4_H

#include <arpa/inet.h>


int pool4_display(void);
int pool4_count(void);
int pool4_add(struct in_addr *addr);
int pool4_remove(struct in_addr *addr);


#endif /* _POOL4_H */
