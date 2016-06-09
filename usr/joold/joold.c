#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include "nat64/usr/joold/modsocket.h"
#include "nat64/usr/joold/netsocket.h"

static void cancel_thread(pthread_t thread)
{
	int error;

	error = pthread_cancel(thread);
	if (!error)
		pthread_join(thread, NULL);
	/*
	 * else:
	 * Well, `man 3 pthread_cancel` just `exit(EXIT_FAILURE)`s when
	 * `pthread_cancel()` fails.
	 * Let's instead be good citizens by closing the sockets anyway.
	 */
}

int main(int argc, char **argv)
{
	pthread_t mod2net_thread;
	pthread_t net2mod_thread;
	int error;

	error = netsocket_init(argc, argv);
	if (error)
		return error;
	error = modsocket_init();
	if (error) {
		netsocket_destroy();
		return error;
	}

	error = pthread_create(&mod2net_thread, NULL, modsocket_listen, NULL);
	if (error) {
		errno = error;
		perror("Module-to-network thread initialization");
		goto end;
	}
	error = pthread_create(&net2mod_thread, NULL, netsocket_listen, NULL);
	if (error) {
		errno = error;
		perror("Network-to-module thread initialization");
		cancel_thread(mod2net_thread);
		goto end;
	}

	pthread_join(net2mod_thread, NULL);
	pthread_join(mod2net_thread, NULL);
	/* Fall through. */

end:
	modsocket_destroy();
	netsocket_destroy();
	return error;
}
