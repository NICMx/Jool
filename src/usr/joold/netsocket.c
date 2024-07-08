#include "usr/joold/netsocket.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "modsocket.h"
#include "common/config.h"
#include "usr/joold/json.h"
#include "usr/joold/log.h"
#include "usr/util/str_utils.h"

struct netsocket_cfg netcfg;

static int sk;
/** Processed version of the configuration's hostname and service. */
static struct addrinfo *addr_candidates;
/** Candidate from @addr_candidates that we managed to bind the socket with. */
static struct addrinfo *bound_address;

atomic_int netsocket_pkts_rcvd;
atomic_int netsocket_bytes_rcvd;
atomic_int netsocket_pkts_sent;
atomic_int netsocket_bytes_sent;

#define _setsockopt(s, p, k, v) setsockopt(sk, p, k, &v, sizeof(v))
#define setsockopt4(sk, key, val) _setsockopt(sk, IPPROTO_IP, key, val)
#define setsockopt6(sk, key, val) _setsockopt(sk, IPPROTO_IPV6, key, val)

static struct in_addr *get_addr4(struct addrinfo *addr)
{
	return &((struct sockaddr_in *)addr->ai_addr)->sin_addr;
}

static struct in6_addr *get_addr6(struct addrinfo *addr)
{
	return &((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr;
}

bool is_multicast4(struct in_addr *addr)
{
	return (addr->s_addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

bool is_multicast6(struct in6_addr *addr)
{
	return (addr->s6_addr32[0] & htonl(0xff000000)) == htonl(0xff000000);
}

int netsocket_config(char const *filename)
{
	cJSON *json;
	int error;

	netcfg.enabled = true;

	error = read_json(filename, &json);
	if (error)
		return error;

	error = json2str(json, "multicast address", &netcfg.mcast_addr);
	if (error)
		goto end;
	error = json2str(json, "multicast port", &netcfg.mcast_port);
	if (error)
		goto end;
	error = json2str(json, "in interface", &netcfg.in_interface);
	if (error)
		goto end;
	error = json2str(json, "out interface", &netcfg.out_interface);
	if (error)
		goto end;
	error = json2int(json, "ttl", &netcfg.ttl);

	if (netcfg.ttl < 0 || 256 < netcfg.ttl) {
		syslog(LOG_ERR, "ttl out of range: %d\n", netcfg.ttl);
		return 1;
	}

end:	cJSON_Delete(json);
	return error;
}

static int try_address(void)
{
	const int yes = 1;

	sk = socket(bound_address->ai_family, bound_address->ai_socktype,
			bound_address->ai_protocol);
	if (sk < 0) {
		pr_perror("socket() failed", errno);
		return 1;
	}

	/* (Do not reorder this. SO_REUSEADDR needs to happen before bind().) */
	syslog(LOG_INFO, "Setting SO_REUSEADDR as %d...", yes);
	/* http://stackoverflow.com/questions/14388706 */
	if (_setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, yes)) {
		pr_perror("setsockopt(SO_REUSEADDR) failed", errno);
		return 1;
	}

	if (bind(sk, bound_address->ai_addr, bound_address->ai_addrlen)) {
		pr_perror("bind() failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "The socket to the network was created.");
	return 0;
}

static int create_socket(void)
{
	struct addrinfo hints = { 0 };
	int err;

	syslog(LOG_INFO, "Getting address info of %s#%s...",
			netcfg.mcast_addr, netcfg.mcast_port);

	hints.ai_socktype = SOCK_DGRAM;
	err = getaddrinfo(netcfg.mcast_addr, netcfg.mcast_port, &hints,
			&addr_candidates);
	if (err) {
		syslog(LOG_ERR, "getaddrinfo() failed: %s", gai_strerror(err));
		return err;
	}

	bound_address = addr_candidates;
	while (bound_address) {
		syslog(LOG_INFO, "Trying an address candidate...");
		err = try_address();
		if (!err)
			return 0;
		bound_address = bound_address->ai_next;
	}

	syslog(LOG_ERR, "None of the candidates yielded a valid socket.");
	freeaddrinfo(addr_candidates);
	return 1;
}

static int mcast4opt_add_membership(void)
{
	struct ip_mreq mreq;
	struct jool_result result;

	mreq.imr_multiaddr = *get_addr4(bound_address);
	if (netcfg.in_interface) {
		result = str_to_addr4(netcfg.in_interface, &mreq.imr_interface);
		if (result.error) {
			pr_result(&result);
			return 1;
		}
	} else {
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	}

	if (setsockopt4(sk, IP_ADD_MEMBERSHIP, mreq)) {
		pr_perror("-> setsockopt(IP_ADD_MEMBERSHIP) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "-> We're now registered to the multicast group.");
	return 0;
}

static int mcast4opt_disable_loopback(void)
{
	int loop = 0;

	if (setsockopt4(sk, IP_MULTICAST_LOOP, loop)) {
		pr_perror("-> setsockopt(IP_MULTICAST_LOOP) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "-> Multicast loopback disabled.");
	return 0;
}

static int mcast4opt_set_ttl(void)
{
	if (setsockopt4(sk, IP_MULTICAST_TTL, netcfg.ttl)) {
		pr_perror("-> setsockopt(IP_MULTICAST_TTL) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "-> Tweaked the TTL of multicasts.");
	return 0;
}

static int mcast4opt_set_out_interface(void)
{
	struct in_addr addr;
	struct jool_result result;

	if (!netcfg.out_interface)
		return 0;

	result = str_to_addr4(netcfg.out_interface, &addr);
	if (result.error) {
		pr_result(&result);
		return 1;
	}

	if (setsockopt4(sk, IP_MULTICAST_IF, addr)) {
		pr_perror("-> setsockopt(IP_MULTICAST_IF) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "-> The outgoing interface was overridden.");
	return 0;
}

static int handle_mcast4_opts()
{
	int error;

	error = mcast4opt_add_membership();
	if (error)
		return error;

	error = mcast4opt_disable_loopback();
	if (error)
		return error;

	error = mcast4opt_set_ttl();
	if (error)
		return error;

	return mcast4opt_set_out_interface();
}

static int mcast6opt_add_membership(void)
{
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = *get_addr6(bound_address);
	if (netcfg.in_interface) {
		mreq.ipv6mr_interface = if_nametoindex(netcfg.in_interface);
		if (!mreq.ipv6mr_interface) {
			pr_perror("The incoming interface name is invalid",
					errno);
			return 1;
		}
	} else {
		mreq.ipv6mr_interface = 0; /* Any interface. */
	}

	if (setsockopt6(sk, IPV6_ADD_MEMBERSHIP, mreq)) {
		pr_perror("setsockopt(IPV6_ADD_MEMBERSHIP) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "We're now registered to the multicast group.");
	return 0;
}

static int mcast6opt_disable_loopback(void)
{
	int loop = 0;

	if (setsockopt6(sk, IPV6_MULTICAST_LOOP, loop)) {
		pr_perror("setsockopt(IP_MULTICAST_LOOP) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "Multicast loopback disabled.");
	return 0;
}

static int mcast6opt_set_ttl(void)
{
	if (setsockopt6(sk, IPV6_MULTICAST_HOPS, netcfg.ttl)) {
		pr_perror("setsockopt(IPV6_MULTICAST_HOPS) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "Tweaked the TTL of multicasts.");
	return 0;
}

static int mcast6opt_set_out_interface(void)
{
	unsigned int interface;

	if (!netcfg.out_interface)
		return 0;

	interface = if_nametoindex(netcfg.out_interface);
	if (!interface) {
		pr_perror("The outgoing interface name is invalid", errno);
		return 1;
	}

	if (setsockopt6(sk, IPV6_MULTICAST_IF, interface)) {
		pr_perror("setsockopt(IP_MULTICAST_IF) failed", errno);
		return 1;
	}

	syslog(LOG_INFO, "The outgoing interface was overridden.");
	return 0;
}

static int handle_mcast6_opts(void)
{
	int error;

	error = mcast6opt_add_membership();
	if (error)
		return error;

	error = mcast6opt_disable_loopback();
	if (error)
		return error;

	error = mcast6opt_set_ttl();
	if (error)
		return error;

	return mcast6opt_set_out_interface();
}

static int adjust_mcast_opts(void)
{
	syslog(LOG_INFO, "Configuring multicast options on the socket...");

	switch (bound_address->ai_family) {
	case AF_INET:
		return handle_mcast4_opts();
	case AF_INET6:
		return handle_mcast6_opts();
	}

	syslog(LOG_INFO, "I don't know how to tweak multicast socket options for address family %d.",
			bound_address->ai_family);
	return 1;
}

static void *netsocket_listen(void *arg)
{
	char buffer[JOOLD_MAX_PAYLOAD];
	int bytes;

	syslog(LOG_INFO, "Listening...");

	do {
		bytes = recv(sk, buffer, sizeof(buffer), 0);
		if (bytes < 0) {
			pr_perror("Error receiving packet from the network",
					errno);
			continue;
		}

		netsocket_pkts_rcvd++;
		netsocket_bytes_rcvd += bytes;

		syslog(LOG_DEBUG, "Received %d bytes from the network.", bytes);
		modsocket_send(buffer, bytes);
	} while (true);

	return NULL;
}

int netsocket_start(void)
{
	pthread_t net_thread;
	int error;

	syslog(LOG_INFO, "Opening netsocket...");

	if (!netcfg.enabled) {
		syslog(LOG_INFO, "Not configured; skipping netsocket.");
		return 0;
	}

	error = create_socket();
	if (error)
		return error;

	error = adjust_mcast_opts();
	if (error)
		return error;

	error = pthread_create(&net_thread, NULL, netsocket_listen, NULL);
	if (error) {
		pr_perror("Unable to start netsocket thread", error);
		return error;
	}

	syslog(LOG_INFO, "Netsocket ready.");
	return 0;
}

void netsocket_send(void *buffer, size_t size)
{
	int bytes;

	syslog(LOG_DEBUG, "Sending %zu bytes to the network...", size);
	bytes = sendto(sk, buffer, size, 0,
			bound_address->ai_addr,
			bound_address->ai_addrlen);
	if (bytes < 0)
		pr_perror("Could not send a packet to the network", errno);
	else {
		syslog(LOG_DEBUG, "Sent %d bytes to the network.\n", bytes);
		netsocket_pkts_sent++;
		netsocket_bytes_sent += bytes;
	}
}
