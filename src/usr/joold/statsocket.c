#include "usr/joold/statsocket.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "usr/joold/log.h"
#include "usr/joold/json.h"

struct statsocket_cfg statcfg;

struct sockfd {
	int fd;
	SLIST_ENTRY(sockfd) hook;
};

SLIST_HEAD(sockfds, sockfd);

extern atomic_int modsocket_pkts_sent;
extern atomic_int modsocket_bytes_sent;
extern atomic_int netsocket_pkts_rcvd;
extern atomic_int netsocket_bytes_rcvd;
extern atomic_int netsocket_pkts_sent;
extern atomic_int netsocket_bytes_sent;

int statsocket_config(char const *filename)
{
	cJSON *json;
	int error;

	statcfg.enabled = true;

	error = read_json(filename, &json);
	if (error)
		return error;

	error = json2str(filename, json, "address", &statcfg.address);
	if (error)
		goto end;
	error = json2str(filename, json, "port", &statcfg.port);

end:	cJSON_Delete(json);
	return error;
}

/* buf must length INET6_ADDRSTRLEN. */
static char const *
addr2str(struct addrinfo *info, char *buf)
{
	struct sockaddr_storage *sockaddr;
	void *addr;
	char const *result;

	sockaddr = (struct sockaddr_storage *) info->ai_addr;
	if (!sockaddr)
		return statcfg.address;

	switch (sockaddr->ss_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *) sockaddr)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *) sockaddr)->sin6_addr;
		break;
	default:
		return statcfg.address;
	}

	result = inet_ntop(sockaddr->ss_family, addr, buf, INET6_ADDRSTRLEN);
	return result ? result : statcfg.address;
}

static int create_sockets(struct sockfds *fds)
{
	struct sockfd *fd;
	struct addrinfo hints = { 0 };
	struct addrinfo *ais, *ai;
	int error;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_PASSIVE;

	error = getaddrinfo(statcfg.address, statcfg.port, &hints, &ais);
	if (error) {
		syslog(LOG_ERR, "getaddrinfo() failed: %s", gai_strerror(error));
		return error;
	}

	for (ai = ais; ai; ai = ai->ai_next) {
		char buf[INET6_ADDRSTRLEN];
		int sk;

		syslog(LOG_INFO, "Trying address '[%s]:%s'...",
				addr2str(ai, buf), statcfg.port);

		sk = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sk < 0) {
			error = errno;
			pr_perror("socket() failed", error);
			return error;
		}

		if (bind(sk, ai->ai_addr, ai->ai_addrlen)) {
			error = errno;
			pr_perror("bind() failed", error);
			return error;
		}

		syslog(LOG_INFO, "Socket bound successfully.");

		fd = malloc(sizeof(struct sockfd));
		if (!fd)
			return ENOMEM;
		fd->fd = sk;
		SLIST_INSERT_HEAD(fds, fd, hook);
	}

	freeaddrinfo(ais);
	return 0;
}

#define BUFFER_SIZE 1024

void *serve_stats(void *arg)
{
	struct sockfd *sfd;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	int nread, nstr, nwritten;
	char buffer[BUFFER_SIZE];

	sfd = (struct sockfd *) arg;

	while (true) {
		peer_addr_len = sizeof(peer_addr);
		nread = recvfrom(sfd->fd, buffer, BUFFER_SIZE, 0,
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

		nwritten = sendto(sfd->fd, buffer, nstr, 0,
				(struct sockaddr *) &peer_addr,
				peer_addr_len);
		if (nwritten != nstr)
			syslog(LOG_ERR, "statsocket error: %s\n", strerror(errno));
	}
}

int statsocket_start(void)
{
	struct sockfds fds;
	struct sockfd *fd;
	pthread_t thread;
	int error;

	syslog(LOG_INFO, "Opening statsocket...");

	if (!statcfg.enabled) {
		syslog(LOG_INFO, "Not configured; skipping statsocket.");
		return 0;
	}

	SLIST_INIT(&fds);

	error = create_sockets(&fds);
	if (error)
		return error;

	SLIST_FOREACH(fd, &fds, hook) {
		error = pthread_create(&thread, NULL, serve_stats, fd);
		if (error) {
			syslog(LOG_ERR, "Unable to start statsocket thread: %s",
					strerror(error));
			return error;
		}
	}

	syslog(LOG_INFO, "Statsocket ready.");
	return 0;
}
