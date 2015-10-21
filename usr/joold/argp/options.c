#include <stdlib.h>
#include <string.h>
#include "nat64/usr/joold/argp/options.h"


static const struct argp_option local_addr = {
		.name = "local_add",
		.key = OPT_LOCAL_ADDRESS,
		.arg = "local_add",
		.flags = 0,
		.doc = "Local IP address which is used to know which device is going to be used to receive multicast traffic.",
		.group = 0
};

static const struct argp_option multicast_addr = {
		.name = "multicast_add",
		.key = OPT_MULTICAST_ADDRESS,
		.arg = "multicast_add",
		.flags = 0,
		.doc = "Multicast address which belongs to the multicast group the application is going to join.",
		.group = 0
};

static const struct argp_option multicast_port = {
		.name = "multicast_port",
		.key = OPT_MULTICAST_PORT,
		.arg = "multicast_port",
		.flags = 0,
		.doc = "Port which will be used to listen and send multicast packets.",
		.group = 0
};

static const struct argp_option ip_version = {
		.name = "ip_version",
		.key = OPT_IP_VERSION,
		.arg = "ip_version",
		.flags = 0,
		.doc = "This parameter indicates if addresses are ipv4 or ipv6, note that both addresses (local and multicast) must be of the same type.",
		.group = 0
};



static const struct argp_option *options[] = {
		&local_addr,
		&multicast_addr,
		&multicast_port,
		&ip_version
};

struct argp_option * build_options() {

	struct argp_option *result;
	size_t template_size = sizeof(options);
	unsigned option_size = sizeof(*result);
	int count = template_size / sizeof(*options);
	unsigned int i;

	result = malloc(option_size* (count+1));

	if (!result)
		return NULL;

	for(i = 0; i < count; i++)
		memcpy(&result[i],options[i],option_size);

	memset(&result[count],0,option_size);

	return result;

}


/* Parse a single option. */
error_t parse_opt (int key, char *arg, struct argp_state *state)
{

  struct arguments *arguments = state->input;

  switch (key) {

  case OPT_LOCAL_ADDRESS:
	  	  arguments->local_address = arg;
  		  break;
  	  case OPT_MULTICAST_ADDRESS:
  		  arguments->multicast_address = arg;
  		  break;
  	  case OPT_MULTICAST_PORT:
  		  arguments->multicast_port = arg;
  		  break;
  	  case OPT_IP_VERSION:
  		  arguments->ip_version = arg;
  		  break;
  	  default:
  		  return ARGP_ERR_UNKNOWN;
  }

  return 0;

}
