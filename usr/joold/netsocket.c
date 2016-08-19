#include "nat64/usr/joold/netsocket.h"

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include "nat64/common/config.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/types.h"
#include "nat64/usr/cJSON.h"
#include "nat64/usr/file.h"
#include "nat64/usr/joold/modsocket.h"

struct netsocket_config {
	/** Address where the sessions will be advertised. Lacks a default. */
	char *mcast_addr;
	/** UDP port where the sessions will be advertised. Lacks a default. */
	char *mcast_port;

	/**
	 * On IPv4, this should be one addresses from the interface where the
	 * multicast traffic is expected to be received.
	 * On IPv6, this should be the name of the interface (eg. "eth0").
	 * Defaults to NULL, which has the kernel choose an interface for us.
	 */
	char *in_interface;
	/** Just like @in_interface, except for outgoing packets. */
	char *out_interface;

	int reuseaddr;
	bool reuseaddr_set;

	int ttl;
	bool ttl_set;
};

static int sk;
/** Processed version of the configuration's hostname and service. */
static struct addrinfo *addr_candidates;
/** Candidate from @addr_candidates that we managed to bind the socket with. */
static struct addrinfo *bound_address;

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

static int json_to_config(cJSON *json, struct netsocket_config *cfg)
{
	char *missing;
	cJSON *child;

	memset(cfg, 0, sizeof(*cfg));

	child = cJSON_GetObjectItem(json, "multicast address");
	if (!child) {
		missing = "multicast address";
		goto fail;
	}
	cfg->mcast_addr = child->valuestring;

	child = cJSON_GetObjectItem(json, "multicast port");
	if (!child) {
		missing = "multicast port";
		goto fail;
	}
	cfg->mcast_port = child->valuestring;

	child = cJSON_GetObjectItem(json, "in interface");
	cfg->in_interface = child ? child->valuestring : NULL;

	child = cJSON_GetObjectItem(json, "out interface");
	cfg->out_interface = child ? child->valuestring : NULL;

	child = cJSON_GetObjectItem(json, "reuseaddr");
	cfg->reuseaddr_set = !!child;
	cfg->reuseaddr = child ? child->valueint : 0;

	child = cJSON_GetObjectItem(json, "ttl");
	cfg->ttl_set = !!child;
	cfg->ttl = child ? child->valueint : 0;

	return 0;

fail:
	log_err("The field '%s' is mandatory; please include it in the file.",
			missing);
	return 1;
}

int read_json(int argc, char **argv, cJSON **result)
{
	char *file_name;
	char *file;
	cJSON *json;
	int error;

	file_name = (argc >= 2) ? argv[1] : "netsocket.json";
	log_info("Opening file %s...", file_name);
	error = file_to_string(file_name, &file);
	if (error)
		return error;

	json = cJSON_Parse(file);
	if (!json) {
		log_err("JSON syntax error.");
		log_err("The JSON parser got confused around about here:");
		log_err("%s", cJSON_GetErrorPtr());
		free(file);
		return 1;
	}

	free(file);
	*result = json;
	return 0;
}

static int try_address(struct netsocket_config *config)
{
	sk = socket(bound_address->ai_family, bound_address->ai_socktype,
			bound_address->ai_protocol);
	if (sk < 0) {
		log_perror("socket() failed", errno);
		return 1;
	}

	/* (Do not reorder this. SO_REUSEADDR needs to happen before bind().) */
	if (config->reuseaddr_set) {
		log_info("Setting SO_REUSEADDR as %d...", config->reuseaddr);
		/* http://stackoverflow.com/questions/14388706 */
		if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &config->reuseaddr,
				sizeof(config->reuseaddr))) {
			log_perror("setsockopt(SO_REUSEADDR) failed", errno);
			return 1;
		}
	}

	if (bind(sk, bound_address->ai_addr, bound_address->ai_addrlen)) {
		log_perror("bind() failed", errno);
		return 1;
	}

	log_info("The socket to the network was created.");
	return 0;
}

static int create_socket(struct netsocket_config *config)
{
	struct addrinfo hints = { 0 };
	int err;

	log_info("Getting address info of %s#%s...",
			config->mcast_addr,
			config->mcast_port);

	hints.ai_socktype = SOCK_DGRAM;
	err = getaddrinfo(config->mcast_addr, config->mcast_port, &hints,
			&addr_candidates);
	if (err) {
		log_err("getaddrinfo() failed: %s", gai_strerror(err));
		return err;
	}

	bound_address = addr_candidates;
	while (bound_address) {
		log_info("Trying an address candidate...");
		err = try_address(config);
		if (!err)
			return 0;
		bound_address = bound_address->ai_next;
	}

	log_err("None of the candidates yielded a valid socket.");
	freeaddrinfo(addr_candidates);
	return 1;
}

static int mcast4opt_add_membership(struct netsocket_config *cfg)
{
	struct ip_mreq mreq;

	mreq.imr_multiaddr = *get_addr4(bound_address);
	if (cfg->in_interface) {
		if (str_to_addr4(cfg->in_interface, &mreq.imr_interface))
			return 1;
	} else {
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	}

	if (setsockopt(sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
			sizeof(mreq))) {
		log_perror("-> setsockopt(IP_ADD_MEMBERSHIP) failed", errno);
		return 1;
	}

	log_info("-> We're now registered to the multicast group.");
	return 0;
}

static int mcast4opt_disable_loopback(void)
{
	int loop = 0;

	if (setsockopt(sk, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
			sizeof(loop))) {
		log_perror("-> setsockopt(IP_MULTICAST_LOOP) failed", errno);
		return 1;
	}

	log_info("-> Multicast loopback disabled.");
	return 0;
}

static int mcast4opt_set_ttl(struct netsocket_config *cfg)
{
	if (!cfg->ttl_set)
		return 0;

	if (setsockopt(sk, IPPROTO_IP, IP_MULTICAST_TTL, &cfg->ttl,
			sizeof(cfg->ttl))) {
		log_perror("-> setsockopt(IP_MULTICAST_TTL) failed", errno);
		return 1;
	}

	log_info("-> Tweaked the TTL of multicasts.");
	return 0;
}

static int mcast4opt_set_out_interface(struct netsocket_config *cfg)
{
	struct in_addr addr;

	if (!cfg->out_interface)
		return 0;

	if (str_to_addr4(cfg->out_interface, &addr))
		return 1;

	if (setsockopt(sk, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr))) {
		log_perror("-> setsockopt(IP_MULTICAST_IF) failed", errno);
		return 1;
	}

	log_info("-> The outgoing interface was overriden.");
	return 0;
}

static int handle_mcast4_opts(struct netsocket_config *cfg)
{
	int error;

	error = mcast4opt_add_membership(cfg);
	if (error)
		return error;

	error = mcast4opt_disable_loopback();
	if (error)
		return error;

	error = mcast4opt_set_ttl(cfg);
	if (error)
		return error;

	return mcast4opt_set_out_interface(cfg);
}

static int mcast6opt_add_membership(struct netsocket_config *cfg)
{
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = *get_addr6(bound_address);
	if (cfg->in_interface) {
		mreq.ipv6mr_interface = if_nametoindex(cfg->in_interface);
		if (!mreq.ipv6mr_interface) {
			log_perror("The incoming interface name is invalid",
					errno);
			return 1;
		}
	} else {
		mreq.ipv6mr_interface = 0; /* Any interface. */
	}

	if (setsockopt(sk, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
			sizeof(mreq))) {
		log_perror("setsockopt(IPV6_ADD_MEMBERSHIP) failed", errno);
		return 1;
	}

	log_info("We're now registered to the multicast group.");
	return 0;
}

static int mcast6opt_disable_loopback(void)
{
	int loop = 0;

	if (setsockopt(sk, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
			sizeof(loop))) {
		log_perror("setsockopt(IP_MULTICAST_LOOP) failed", errno);
		return 1;
	}

	log_info("Multicast loopback disabled.");
	return 0;
}

static int mcast6opt_set_ttl(struct netsocket_config *cfg)
{
	if (!cfg->ttl_set)
		return 0;

	if (setsockopt(sk, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &cfg->ttl,
			sizeof(cfg->ttl))) {
		log_perror("setsockopt(IPV6_MULTICAST_HOPS) failed", errno);
		return 1;
	}

	log_info("Tweaked the TTL of multicasts.");
	return 0;
}

static int mcast6opt_set_out_interface(struct netsocket_config *cfg)
{
	unsigned int interface;

	if (!cfg->out_interface)
		return 0;

	interface = if_nametoindex(cfg->out_interface);
	if (!interface) {
		log_perror("The outgoing interface name is invalid", errno);
		return 1;
	}

	if (setsockopt(sk, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface,
			sizeof(interface))) {
		log_perror("setsockopt(IP_MULTICAST_IF) failed", errno);
		return 1;
	}

	log_info("The outgoing interface was overriden.");
	return 0;
}

static int handle_mcast6_opts(struct netsocket_config *cfg)
{
	int error;

	error = mcast6opt_add_membership(cfg);
	if (error)
		return error;

	error = mcast6opt_disable_loopback();
	if (error)
		return error;

	error = mcast6opt_set_ttl(cfg);
	if (error)
		return error;

	return mcast6opt_set_out_interface(cfg);
}

static int adjust_mcast_opts(struct netsocket_config *cfg)
{
	log_info("Configuring multicast options on the socket...");

	switch (bound_address->ai_family) {
	case AF_INET:
		return handle_mcast4_opts(cfg);
	case AF_INET6:
		return handle_mcast6_opts(cfg);
	}

	log_info("I don't know how to tweak multicast socket options for address family %d.",
			bound_address->ai_family);
	return 1;
}

int netsocket_init(int argc, char **argv)
{
	cJSON *json;
	struct netsocket_config cfg;
	int error;

	error = read_json(argc, argv, &json);
	if (error)
		return error;

	error = json_to_config(json, &cfg);
	if (error)
		goto end;

	error = create_socket(&cfg);
	if (error)
		goto end;

	error = adjust_mcast_opts(&cfg);
	if (error) {
		close(sk);
		freeaddrinfo(addr_candidates);
		goto end;
	}
	/* Fall through. */

end:
	cJSON_Delete(json);
	return error;
}

void netsocket_destroy(void)
{
	close(sk);
	freeaddrinfo(addr_candidates);
}

void *netsocket_listen(void *arg)
{
	char buffer[JOOLD_MAX_PAYLOAD];
	int bytes;

	log_info("Listening...");

	do {
		bytes = recv(sk, buffer, sizeof(buffer), 0);
		if (bytes < 0) {
			log_perror("Error receiving packet from the network",
					errno);
			continue;
		}

		log_debug("Received %d bytes from the network.", bytes);
		modsocket_send(buffer, bytes);
	} while (true);

	return NULL;
}

void netsocket_send(void *buffer, size_t size)
{
	int bytes;

	log_debug("Sending %zu bytes to the network...", size);
	bytes = sendto(sk, buffer, size, 0,
			bound_address->ai_addr,
			bound_address->ai_addrlen);
	if (bytes < 0)
		log_perror("Could not send a packet to the network", errno);
	else
		log_debug("Sent %d bytes to the network.\n", bytes);
}
