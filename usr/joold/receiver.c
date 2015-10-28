#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "nat64/usr/joold/mcastutil.h"
#include "nat64/usr/joold/jool_client.h"

static int sockfd;
static char *lipaddress;
static char b[2048];
static struct sockaddr_storage clientaddr, addr;
static socklen_t addrlen;
static char clienthost[NI_MAXHOST];
static char clientservice[NI_MAXSERV];

int receiver_init(char * multicast_address, char * local_ip_address,
		char * port) {

	lipaddress = local_ip_address;

	memset(&addr, 0, sizeof(addr));

	if (get_addr(multicast_address, port, PF_UNSPEC,
	SOCK_DGRAM, &addr) < 0) {
		fprintf(stderr, "get_addr error:: could not find multicast "
				"address=[%s] port=[%s]\n", multicast_address, port);
		return -1;
	}

	if (isMulticast(&addr) < 0) {
		fprintf(stderr, "This address does not seem a multicast address [%s]\n",
				multicast_address);
		return -1;
	}

	sockfd = socket(addr.ss_family, SOCK_DGRAM, 0);

	if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind error:: ");
		close(sockfd);
		return -1;
	}

	if (joinGroup(sockfd, 0, 8, 1, &addr) < 0) {
		close(sockfd);
		return -1;
	}

	return 0;
}

void *receiver_start(void *args) {

	int n;
	printf("Starting receiver.");
	addrlen = sizeof(clientaddr);
	for (;;) {
		n = recvfrom(sockfd, b, sizeof(b), 0, (struct sockaddr *) &clientaddr,
				&addrlen);

		if (n < 0)
			continue;

		memset(clienthost, 0, sizeof(clienthost));
		memset(clientservice, 0, sizeof(clientservice));

		getnameinfo((struct sockaddr *) &clientaddr, addrlen, clienthost,
				sizeof(clienthost), clientservice, sizeof(clientservice),
				NI_NUMERICHOST);

		if (strcmp(clienthost, lipaddress) == 0)
			continue;

		n = set_updated_entries(b);

		printf("Received request from host=[%s] port=[%s]\n", clienthost,
				clientservice);
		fflush(stdout);

	}
	return 0;
}
