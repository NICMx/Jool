#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>


int get_addr (const char *hostname,
          const char *service,
          int         family,
          int         socktype,
          struct sockaddr_storage *addr)
{
    struct addrinfo hints, *res, *ressave;
    int n, sockfd, retval;

    retval = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = socktype;

    n = getaddrinfo(hostname, service, &hints, &res);

    if (n <0) {
        fprintf(stderr, "getaddrinfo error:: [%s]\n", gai_strerror(n)) ;
        return retval;
    }

    ressave = res;

    sockfd=-1;
    while (res) {
        sockfd = socket(res->ai_family,
                        res->ai_socktype,
                        res->ai_protocol);


        if (!(sockfd < 0)) {
        	if (bind(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
        		close(sockfd);
                memcpy(addr, res->ai_addr, sizeof(*addr));

                freeaddrinfo(ressave);
                return 0;
            }
            close(sockfd);
            sockfd=-1;

        }
        res=res->ai_next;
    }

    freeaddrinfo(ressave);

    return retval;
}

int joinGroup(int sockfd, int loopBack, int mcastTTL, int reuseAddr,
          struct sockaddr_storage *addr)
{
    int r1, r2, r3, r4, retval;

    retval=-1;

    switch (addr->ss_family) {
        case AF_INET: {
            struct ip_mreq      mreq;

            mreq.imr_multiaddr.s_addr=
                ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            mreq.imr_interface.s_addr= INADDR_ANY;

            r1= setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
                           &loopBack, sizeof(loopBack));
            if (r1<0)
                perror("joinGroup:: IP_MULTICAST_LOOP:: ");

            r2= setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL,
                           &mcastTTL, sizeof(mcastTTL));
            if (r2<0)
               perror("joinGroup:: IP_MULTICAST_TTL:: ");

            r3= setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           (const void *)&mreq, sizeof(mreq));
            if (r3<0)
                perror("joinGroup:: IP_ADD_MEMBERSHIP:: ");

            r4= setsockopt(sockfd, IPPROTO_IP,SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));

            if (r4 <0)
            	 perror("reuseAddress:: SO_REUSEADDR:: ") ;

        } break;

        case AF_INET6: {
           struct ipv6_mreq    mreq6;

           memcpy(&mreq6.ipv6mr_multiaddr,
                  &(((struct sockaddr_in6 *)addr)->sin6_addr),
                  sizeof(struct in6_addr));

           mreq6.ipv6mr_interface= 0; // cualquier interfaz

           r1= setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                          &loopBack, sizeof(loopBack));
           if (r1<0)
               perror("joinGroup:: IPV6_MULTICAST_LOOP:: ");

           r2= setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                          &mcastTTL, sizeof(mcastTTL));
           if (r2<0)
               perror("joinGroup:: IPV6_MULTICAST_HOPS::  ");

           r3= setsockopt(sockfd, IPPROTO_IPV6,
                          IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6));
           if (r3<0)
              perror("joinGroup:: IPV6_ADD_MEMBERSHIP:: ");

          r4= setsockopt(sockfd, IPPROTO_IPV6,SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));

           if (r4 <0)
        	  perror("reuseAddress:: SO_REUSEADDR:: ") ;

        } break;

        default:
            r1=r2=r3=r4=-1;
    }



    if ((r1>=0) && (r2>=0) && (r3>=0) && (r4>=0))
        retval=0;

    return retval;
}


int isMulticast(struct sockaddr_storage *addr)
{
    int retVal;

    retVal=-1;

    switch (addr->ss_family) {
        case AF_INET: {
            struct sockaddr_in *addr4=(struct sockaddr_in *)addr;
            retVal = IN_MULTICAST(ntohl(addr4->sin_addr.s_addr));
        } break;

        case AF_INET6: {
            struct sockaddr_in6 *addr6=(struct sockaddr_in6 *)addr;
            retVal = IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr);
        } break;

        default:
           ;
    }

    return retVal;
}
