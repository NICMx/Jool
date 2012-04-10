/* 
 * From: http://stackoverflow.com/questions/862964/who-can-give-me-the-latest-netlink-programming-samples
 * Library needed: libnl
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/version.h>
#include "../include/xt_nat64_module_comm.h"
#define MY_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary but is the same for kern/usr
#define IPV4_LEN	sizeof("255.255.255.255")

// include code if compiled with libnl version >= 3.1 *
#if LIBNL_VER_NUM < LIBNL_VER(3,1)

void print_nat64_run_conf(struct nat64_run_conf nrc)
{
	printf("NAT64, running configuration,\n");
	printf("\t+ IPv4 pool:\n");
	printf("\t\t- First IP addr: %s,\n", nrc.ipv4_addr_str);
	printf("\t\t- Netmask bits: %d,\n", nrc.ipv4_mask_bits);
}
        
int main(int argc, char *argv[])
{
    struct nl_sock *nls;
//    char msg[] = { 0xde, 0xad, 0xbe, 0xef, 0x90, 0x0d, 0xbe, 0xef };
    //char *msg;
    int ret;
    //unsigned char ipv4_addr[sizeof(struct in6_addr)];
    struct in_addr ipaddr;
    int domain;
    int s;
    char ipstr[IPV4_LEN];
    char buf[INET_ADDRSTRLEN];
    
    char *ipv4_pool_1st = "192.168.1.2";

	struct nat64_run_conf nrc;


	//if (argc != 2) { printf("Usage: %s [\"message\"]\n", argv[0]); return EXIT_FAILURE;}

    nls = nl_socket_alloc();
    if (!nls) {
        printf("bad nl_socket_alloc\n");
        return EXIT_FAILURE;
    }

	// Bind and connect the socket to a protocol
    ret = nl_connect(nls, NETLINK_USERSOCK);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
        nl_socket_free(nls);
        return EXIT_FAILURE;
    }

	// easly send a bunch of payload encapsulated in a netlink message header.
	/* send a string *
    ret = nl_send_simple(nls, MY_MSG_TYPE, 0, msg, strlen(msg)); // Replaced sizeof by strlen. Rob.
    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        printf("Error sending message, is module loaded?\n");
        nl_close(nls);
        nl_socket_free(nls);
        return EXIT_FAILURE;
    } else {
        printf("Message sent (%d bytes): %s\n", ret, msg);
    }
	*/
	
	/* send a ip binary address * 
	strcpy(ipstr, ipv4_pool_1st);
	domain = AF_INET;
	s = inet_pton(domain, ipstr, &(ipaddr.s_addr));
	if (s <= 0) {
               if (s == 0)
                   fprintf(stderr, "Not in presentation format");
               else
                   perror("inet_pton");
               exit(EXIT_FAILURE);
	}
	
    ret = nl_send_simple(nls, MY_MSG_TYPE, 0, &(ipaddr.s_addr), sizeof(ipaddr));
    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        printf("Error sending message, is module loaded?\n");
        nl_close(nls);
        nl_socket_free(nls);
        return EXIT_FAILURE;
    } else {
    	inet_ntop(AF_INET, &(ipaddr.s_addr), buf, INET_ADDRSTRLEN);
        printf("Message sent (%d bytes): %s\n", ret, buf);
    }
	*/
	
	/* send a ip binary address * */
	strcpy(nrc.ipv4_addr_str, ipv4_pool_1st);
	nrc.ipv4_mask_bits = 24;	 
	
    ret = nl_send_simple(nls, MY_MSG_TYPE, 0, &(nrc), sizeof(nrc));
    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        printf("Error sending message, is module loaded?\n");
        nl_close(nls);
        nl_socket_free(nls);
        return EXIT_FAILURE;
    } else {        
	    printf("Message sent (%d bytes):\n", ret);
        print_nat64_run_conf(nrc);
    }
		

    nl_close(nls);
    nl_socket_free(nls);

    return EXIT_SUCCESS;
}
#endif


