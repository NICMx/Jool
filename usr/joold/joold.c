#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include "nat64/usr/joold/modsocket.h"
#include "nat64/usr/joold/netsocket.h"

int main(int argc, char **argv)
{
	/* TODO reverts. */

	pthread_t mod2net_thread;
	pthread_t net2mod_thread;
	int error;

	error = netsocket_init(argc, argv);
	if (error)
		return error;
	error = modsocket_init();
	if (error)
		return error;

	error = pthread_create(&mod2net_thread, NULL, modsocket_listen, NULL);
	if (error) {
		errno = error;
		perror("Module-to-network thread initialization");
		return error;
	}
	error = pthread_create(&net2mod_thread, NULL, netsocket_listen, NULL);
	if (error) {
		errno = error;
		perror("Module-to-network thread initialization");
		return error;
	}

	/* TODO handle return values? */
	pthread_join(mod2net_thread, NULL);
	pthread_join(net2mod_thread, NULL);

	return 0;
}
