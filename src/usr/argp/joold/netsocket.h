#ifndef SRC_USR_ARGP_JOOLD_NETSOCKET_H_
#define SRC_USR_ARGP_JOOLD_NETSOCKET_H_

/* This is the socket we use to talk to other joold instances in the network. */

#include <stdbool.h>
#include <stddef.h>

struct netsocket_cfg {
	bool enabled;
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

	int ttl;
};

int netsocket_start(struct netsocket_cfg *);
bool netsocket_enabled(void);
void netsocket_send(void *buffer, size_t size);

#endif /* SRC_USR_ARGP_JOOLD_NETSOCKET_H_ */
