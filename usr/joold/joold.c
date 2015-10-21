#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <argp.h>
#include <string.h>
#include <regex.h>
#include "nat64/usr/joold/receiver.h"
#include "nat64/usr/joold/sender.h"
#include "nat64/usr/joold/argp/options.h"
#include "nat64/usr/types.h"


int init_threads(char *multicast_address, char *local_ip_address, char *multicast_port) {

		pthread_t thread1, thread2;
		int ret;

		if (receiver_init(multicast_address, local_ip_address,multicast_port)) {
			log_err("Couldn't initialize receiver socket!.");
			return -1;
		}

		if (sender_init(multicast_address,multicast_port)) {
			log_err("Couldn't initialize sender socket!.");
			return -1;
		}

		ret = pthread_create(&thread1, NULL, receiver_start, NULL) ;
		if (ret) {
			log_err("Error - pthread_create() return code: %d\n",ret);
			return ret;
		}

		ret = pthread_create(&thread2, NULL, sender_start, NULL);
		if (ret) {
			log_err("Error - pthread_create() return code: %d\n",ret);
			return ret;
		}

		pthread_join(thread1, NULL);
		pthread_join(thread2, NULL);


		return 0;
}

int main_wrapped(int argc, char **argv) {

	struct arguments arguments;
	struct argp argp_struct = {build_options(),parse_opt,"",""};
	struct in6_addr ipv6_addr;
	struct in_addr ipv4_addr;


    int error = 0;
    char * integer_regex = "[0-9]\\d*";
    regex_t regex;

    error = argp_parse(&argp_struct, argc, argv, 0, 0, &arguments) ;
    if (error)
    	goto _error;

    if(arguments.ip_version == NULL) {
    	log_err("Must set ip_version argument!\n");
    	goto _error;
    }

    if(arguments.local_address == NULL) {
    	log_err("Must set local_address argument!\n");
    	goto _error;
    }

    if(arguments.multicast_address == NULL) {
    	log_err("Must set multicast_address argument!\n");
    	goto _error;
    }

    if(arguments.multicast_port == NULL) {
    	log_err("Must set multicast_port argument!\n");
    	goto _error;
    }

   if(strcmp(arguments.ip_version,"4") && strcmp(arguments.ip_version,"6")) {
	   log_err("Inválid ip_version argument value, must be either \"6\" or \"4\" (without double quotes).\n");
	   return -EINVAL;
   }



   if(!strcmp(arguments.ip_version,"4")) {

	   if (!inet_pton(AF_INET,arguments.local_address, &ipv4_addr)) {
		   log_err("%s: %s is not a valid %s address!.\n","local_address",arguments.local_address,"IPV4");
		   return -EINVAL;
	   }

	   if (!inet_pton(AF_INET,arguments.multicast_address,&ipv4_addr)) {
		   log_err("%s: %s is not a valid %s address!.\n","multicast_address",arguments.local_address,"IPV4");
		   return -EINVAL;
	   }

   } else {

	  if (!inet_pton(AF_INET6,arguments.local_address, &ipv6_addr)) {
		   log_err("%s: %s is not a valid %s address!.\n","local_address",arguments.local_address,"IPV6");
		   return -EINVAL;
	  }

	  if (!inet_pton(AF_INET6,arguments.multicast_address,&ipv6_addr)) {
		  log_err("%s: %s is not a valid %s address!.\n","multicast_address",arguments.local_address,"IPV6");
		 return -EINVAL;
	  }

   }

   if (regcomp(&regex,integer_regex,0)) {
	   log_err("Couldn't compile integer regular expression!.\n");
	   return -1;
   }

   if (regexec(&regex,arguments.multicast_port,0,NULL,0)) {
	   log_err("Invalid multicast_port argument value, must be a valid integer!.\n");
	   return -EINVAL;
   }

   return init_threads(arguments.multicast_address, arguments.local_address, arguments.multicast_port);

   _error:
   argp_help(&argp_struct,stdout,ARGP_HELP_USAGE,"");
   fflush(stdout);
   return -1;
}

int main(int argc, char **argv) {

	return main_wrapped(argc,argv) ;
}
