#include "usr/joold/statsocket.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"

static int create_socket(char const *port, int *fd)
{
	int sk;
	struct addrinfo hints = { 0 };
	struct addrinfo *ais, *ai;
	int err;

	syslog(LOG_INFO, "Setting up statsocket (port %s)...", port);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_PASSIVE;

	err = getaddrinfo(NULL, port, &hints, &ais);
	if (err) {
		syslog(LOG_ERR, "getaddrinfo() failed: %s", gai_strerror(err));
		return err;
	}

	for (ai = ais; ai; ai = ai->ai_next) {
		syslog(LOG_INFO, "Trying an address candidate...");

		sk = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sk < 0) {
			pr_perror("socket() failed", errno);
			continue;
		}

		if (bind(sk, ai->ai_addr, ai->ai_addrlen)) {
			pr_perror("bind() failed", errno);
			close(sk);
			continue;
		}

		syslog(LOG_INFO, "Statsocket created successfully.");
		freeaddrinfo(ais);
		*fd = sk;
		return 0;
	}

	syslog(LOG_ERR, "None of the candidates yielded a valid statsocket.");
	freeaddrinfo(ais);
	return 1;
}

extern atomic_int modsocket_pkts_sent;
extern atomic_int modsocket_bytes_sent;
extern atomic_int netsocket_pkts_rcvd;
extern atomic_int netsocket_bytes_rcvd;
extern atomic_int netsocket_pkts_sent;
extern atomic_int netsocket_bytes_sent;

#define BUFFER_SIZE 1024

void *serve_stats(void *arg)
{
	int sk;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	int nread, nstr, nwritten;
	char buffer[BUFFER_SIZE];

	sk = *((int *)arg);
	free(arg);

	while (true) {
		peer_addr_len = sizeof(peer_addr);
		nread = recvfrom(sk, buffer, BUFFER_SIZE, 0,
				(struct sockaddr *) &peer_addr,
				&peer_addr_len);
		if (nread == -1)
			continue; /* Ignore failed request */

		nstr = snprintf(buffer, BUFFER_SIZE,
				"KERNEL_SENT_PKTS,%d\nKERNEL_SENT_BYTES,%d\n"
				"NET_RCVD_PKTS,%d\nNET_RCVD_BYTES,%d\n"
				"NET_SENT_PKTS,%d\nNET_SENT_BYTES,%d\n",
				modsocket_pkts_sent, modsocket_bytes_sent,
				netsocket_pkts_rcvd, netsocket_bytes_rcvd,
				netsocket_pkts_sent, netsocket_bytes_sent);
		if (nstr >= BUFFER_SIZE)
			snprintf(buffer, BUFFER_SIZE, "Bug!");

		nwritten = sendto(sk, buffer, nstr, 0,
				(struct sockaddr *) &peer_addr,
				peer_addr_len);
		if (nwritten != nstr)
			syslog(LOG_ERR, "statsocket error: %s\n", strerror(errno));
	}
}

int statsocket_start(int argc, char **argv)
{
	int sk, *sk2;
	pthread_t thread;
	int error;

	if (argc < 3) {
		syslog(LOG_INFO, "statsocket port unavailable; skipping statsocket.");
		return 0;
	}

	error = create_socket(argv[2], &sk);
	if (error)
		return error;

	sk2 = malloc(sizeof(int));
	if (!sk2)
		return -ENOMEM;
	*sk2 = sk;

	error = pthread_create(&thread, NULL, serve_stats, sk2);
	if (error) {
		free(sk2);
		close(sk);
	}

	return error;
}
