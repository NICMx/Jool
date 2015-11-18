#ifndef ARGP_OPTIONS_H
#define ARGP_OPTIONS_H

#include <argp.h>

enum argp_flags {
	OPT_LOCAL_ADDRESS = 'l',
	OPT_MULTICAST_ADDRESS = 'm',
	OPT_MULTICAST_PORT = 'p',
	OPT_IP_VERSION = 'v'
};



struct arguments
{
	char * local_address;
	char * multicast_address;
	char * multicast_port;
	char * ip_version;
};

error_t parse_opt (int key, char *arg, struct argp_state *state);
struct argp_option * build_options();

#endif
