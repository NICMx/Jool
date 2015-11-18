#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>

#include "nat64/usr/joold/mcastutil.h"
#include "nat64/usr/joold/jool_client.h"

	static int sockfd,n;
	static struct addrinfo * dst_addr;



int send_payload(void * payload, size_t size) {

		n = sendto(sockfd, payload, size, MSG_DONTWAIT,
		            dst_addr->ai_addr, sizeof(*dst_addr->ai_addr));
		printf("message has been sent.");
		fflush(stdout);

		if (n<0) {
			perror("sendto error:: ");
			close(sockfd);
			return -1;
		}

		if (n<0) {
		  perror("sendto error:: ");
		  close(sockfd);
		  return -1;
		}

		return 0;

}


int sender_init(char * multicast_address, char * multicast_port)
{
	int error;

	error = getaddrinfo(multicast_address, multicast_port, NULL, &dst_addr);
	if (error) {
		printf("getaddrinfo() error: %s\n", gai_strerror(error));
		return error;
	}

	printf("Creating socket.\n");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		error = errno;
		printf("socket() error: %d (%s)\n", error, strerror(error));
		freeaddrinfo(dst_addr);
		return error;
	}

	jool_client_init(send_payload);

	return 0;

}


void *sender_start(void *args) {

	for	(;;) {

		if (get_updated_entries()) {
			fprintf(stderr,"An error occurred while sending synchronization data!!\n");
			fflush(stdout);
		}

	}

	return 0;
}
