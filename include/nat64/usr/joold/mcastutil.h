#ifndef MCAST_UTIL_H
#define MCAST_UTIL_H

int get_addr (const char *hostname,
          const char *service,
          int         family,
          int         socktype,
          struct sockaddr_storage *addr);

int joinGroup(int sockfd, int loopBack, int mcastTTL, int reuseAddr, struct sockaddr_storage *addr);


int isMulticast(struct sockaddr_storage *addr);

#endif
