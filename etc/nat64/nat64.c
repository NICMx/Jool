#include "nat64.h"

const char *argp_program_version =
"nat64 user space 0.1";

const char *argp_program_bug_address =
"<maggonzz@gmail.com>";

struct in6_addr i6addrf,i6addrf1;  
struct in_addr i4addrf,i4addrf1;  
char * pch;
int i,cont;

struct ipv6_prefixes **ipv6_pref = NULL;
unsigned char ipv6_pref_qty;
__u16 mtup_count;
__u16 *mtus = NULL; 
__u16 * mtutemp;

/* This structure is used by main to communicate with parse_opt. */
struct arguments
{
  char *args[2];            /* ARG1 and ARG2 */
  int verbose;              /* The -v flag */
  char *dir6,*pref,*dir4,*remote6,*remote4,*local6,*local4,*first,*last,*hairpin,*mtus;
  int l3_protocol,l4_protocol;
  int estatica;
  unsigned short mode;
  unsigned short op;
  __u64 submode;
  __u16 tail,head,mtu6,mtu4;
  __u8 tclass4;
 char *b1,*b2,*b3,*b4,*b5,*b6,*b7,*b8;
};

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] =
{
  {"verbose",'v', 0, 0, "Produce verbose output."},

  { 0, 0, 0, 0, "BIB Options:", 19},
  {"bib",'b', 0, 0, "operate on BIBs."},
  {"display",'d', 0, 0, "show tables (-b, -s) or pool (-4, -6)."},
  {"static",669, 0, 0, "show static only."},
  {"icmp", 'i', 0, 0, "operate on the ICMP table."},
  {"tcp",'t', 0, 0, "operate on the TCP table."},
  {"udp",'u', 0, 0, "operate on the UDP table."},
  {"ipv4",440, "IP#port", 0, "The following is an address, port, or IPv4 address and port."},
  {"ipv6",660, "IP#port", 0, "The following is an address, port, or IPv6 address and port."},


  { 0, 0, 0, 0, "Session Options:", 20},
  {"session",'s', 0, 0, "operate on the session tables."},
  {"static",669, 0, 0, "show static only."},
  {"display",'d', 0, 0, "show tables (-b, -s) or pool (-4, -6)."},
  {"add",'a', 0, 0, "Add a record to a table (-b,-s) or addresses to a pool (-4, -6)."},
  {"remove",'r', 0, 0, "Remove a record from a table (-b,-s) or addresses from a pool (-4, -6)."},
  {"icmp", 'i', 0, 0, "operate on the ICMP table."},
  {"tcp",'t', 0, 0, "operate on the TCP table."},
  {"udp",'u', 0, 0, "operate on the UDP table."},
  {"remote6",666, "IP#port", 0, "The following is address, port, or address and port of the remote machine in the IPv6 network."},
  {"local6",6666, "IP#port", 0, "The following is address, port, or address and port of the local machine in the IPv6 network."},

  {"remote4",444, "IP#port", 0, "The following is address, port, or address and port of the remote machine in the IPv4 network."},
  {"local4",4444, "IP#port", 0, "The following is address, port, or address and port of the local machine in the IPv4 network."},


  { 0, 0, 0, 0, "IPv6 Pool Options:", 10},
  {"pool6",'6', 0, 0, "operate on  IPv6 pool."},
  {"pref",600, "IP/mask", 0, "IPv6 Prefix."},
  {"display",'d', 0, 0, "show tables (-b, -s) or pool (-4, -6)."},
  {"add",'a', 0, 0, "Add a record to a table (-b,-s) or addresses to a pool (-4, -6)."},
  {"remove",'r', 0, 0, "Remove a record from a table (-b,-s) or addresses from a pool (-4, -6)."},

  { 0, 0, 0, 0, "IPv4 Pool Options:", 11},
  {"pool4",'4', 0, 0, "operate on the IPv4 pool."},
  {"first",601, "IP", 0, "first IPv4 range."},
  {"last",602, "IP", 0, "last IPv4 range."},
  {"display",'d', 0, 0, "show tables (-b, -s) or pool (-4, -6)."},
  {"add",'a', 0, 0, "Add a record to a table (-b,-s) or addresses to a pool (-4, -6)."},
  {"remove",'r', 0, 0, "Remove a record from a table (-b,-s) or addresses from a pool (-4, -6)."},

  { 0, 0, 0, 0, "Hairpinning Options:", 12},
  {"hairpinning",'h', "on/off", 0, "operate on hairpinning."},

 { 0, 0, 0, 0, "Translator Options:", 13},
  {"trans",1200, 0, 0, "operate on translator options"},
  {"head",1201, "NUM", 0, "Packet head room."},
  {"tail",1202, "NUM", 0, "Packet tail room."},
  {"o6tclass",1203, "true/false", 0, "Override IPv6 Traffic class."},
  {"o4tclass",1204, "true/false", 0, "Override IPv4 Traffic class."},
  {"4tclass",1205, "NUM", 0, "IPv4 Traffic class."},
  {"df",1206, "true/false", 0, "Always set Don't Fragment."},
  {"genid",1207, "true/false", 0, "Generate IPv4 ID."},
  {"imp_mtu_rate",1208, "true/false", 0, "Improve MTU failure rate."},
  {"min_ipv6_mtu",1209, "NUM", 0, "Specifies minimal MTU value used in IPv6 network."},
  {"min_ipv4_mtu",1210, "NUM", 0, "Specifies minimal MTU value used in IPv4 network."},
  {"mtu_plateau",1211, "NUM", 0, "MTU plateaus."},
  {"adf",1212, "true/false", 0, "Use Address-Dependent Filtering."},
  {"finfo",1213, "true/false", 0, "Filter ICMPv6 Informational packets."},
  {"droptcp",1214, "true/false", 0, "Drop externally initiated TCP connections"},
  {0}

};

/*
   PARSER. Field 2 in ARGP.
   Order of parameters: KEY, ARG, STATE.
*/
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = 1;
      break;
    case '4':
	  //arguments->l3_protocol = 0;
	  arguments->mode = 3;
      break;
    case '6':
	  //arguments->l3_protocol = 46;
	  arguments->mode = 2;
      break;
    case 'h':
	  arguments->mode = 4;
      arguments->hairpin = arg;
      break;
 	case 440:
	  arguments->dir4 = arg;
      break;
 	case 660:
	  arguments->dir6 = arg;
      break;
    case 669:
      arguments->estatica = 1;
      break;
 	case 444:
      arguments->remote4 = arg;
      break;
	case 600:
      arguments->pref = arg;
      break;
	case 601:
      arguments->first = arg;
      break;
	case 602:
      arguments->last = arg;
      break;
	case 666:
      arguments->remote6 = arg;
      break;
	case 1200:
      arguments->mode= 5;
      break;
	case 1201:
      arguments->head= atoi(arg);
	  arguments->submode |= PHR_MASK;
      break;
	case 1202:
      arguments->tail= atoi(arg);
 	  arguments->submode |= PTR_MASK;
      break;
	case 1203:
 	  arguments->submode |= OIPV6_MASK;
      arguments->b1 = arg;
      break;
	case 1204:
 	  arguments->submode |= OIPV4_MASK;
      arguments->b2 = arg;
      break;
	case 1205:
      arguments->tclass4= atoi(arg);
 	  arguments->submode |= IPV4_TRAFFIC_MASK;
      break;
	case 1206:
 	  arguments->submode |= DF_ALWAYS_MASK;
      arguments->b3 = arg;
      break;
	case 1207:
 	  arguments->submode |= GEN_IPV4_MASK;
      arguments->b4 = arg;
      break;
	case 1208:
 	  arguments->submode |= IMP_MTU_FAIL_MASK;
      arguments->b5 = arg;
      break;
	case 1209:
      arguments->mtu6= atoi(arg);
 	  arguments->submode |= IPV6_NEXTHOP_MASK;
      break;
	case 1210:
      arguments->mtu4= atoi(arg);
 	  arguments->submode |= IPV4_NEXTHOP_MASK;
      break;
	case 1211:
      arguments->mtus= arg;
 	  arguments->submode |= MTU_PLATEAUS_MASK;
 	  arguments->submode |= MTU_PLATEAU_COUNT_MASK;
      break;
	case 1212:
 	  arguments->submode |= ADDRESS_DEPENDENT_FILTER_MASK;
      arguments->b6 = arg;
	case 1213:
 	  arguments->submode |= FILTER_INFO_MASK;
      arguments->b7 = arg;
	case 1214:
 	  arguments->submode |= DROP_TCP_MASK;
      arguments->b8 = arg;
 	case 4444:
      arguments->local4 = arg;
      break;
	case 6666:
      arguments->local6 = arg;
      break;
    case 'a':
	  arguments->op = 0;
      break;
    case 'b':
	  arguments->mode = 0;
      break;
    case 'd':
	  arguments->op = 2;
      break;
    case 's':
	  arguments->mode = 1;
      break;
    case 'r':
	  arguments->op = 1;
      break;
    case 'i':
	  arguments->l4_protocol = 1;
      break;
    case 'u':
	  arguments->l4_protocol = 17;
      break;
    case 't':
	  arguments->l4_protocol = 6;
      break;
 	//case ARGP_KEY_END:
      //     if (state->arg_num < 1)
             /* Not enough arguments. */
        //     argp_usage (state);
          // break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/*
   ARGS_DOC. Field 3 in ARGP.
   A description of the non-option command-line arguments
     that we accept.
*/
static char args_doc[] = "";

/*
  DOC.  Field 4 in ARGP.
  Program documentation.
*/
static char doc[] =
"nat64 -- User space program to configure NAT64.\vFrom the GNU C Tutorial.";

/*
   The ARGP structure itself.
*/
static struct argp argp = {options, parse_opt, args_doc, doc};


int kernel_response(struct nl_msg *msg, void *arg){
	struct answer_struct *as = nlmsg_data(nlmsg_hdr(msg));
	__u64 as_len = nlmsg_datalen(nlmsg_hdr(msg));
	void *payload = as + 1;
	char str[INET6_ADDRSTRLEN];

	switch (as->mode) {
	case 0:
		if (as->operation == 2 && as->array_quantity <= 0 ) {
			printf("Result: %s\n", (unsigned char *) payload);
		} else if (as->operation == 2 && as->array_quantity > 0)  {
			struct bib_entry *entries = payload;

			for (i=0; i<as->array_quantity; i++){
				struct bib_entry *current = &entries[i];
				inet_ntop(AF_INET6, &(current->ipv6.address), str, INET6_ADDRSTRLEN);
				printf("BIB: %s:%d, %s#%d\n",
						inet_ntoa(current->ipv4.address), ntohs(current->ipv4.pi.port),
						str, ntohs(current->ipv6.pi.port));
			}
		}
		break;

	case 1:
		if (as->operation == 0 || as->operation == 1 ) {
			printf("Result: %s\n", (unsigned char *) payload);
		}

		if (as->operation == 2 && as->array_quantity <= 0 ) {
			printf("Result: %s\n", (unsigned char *) payload);
		} else if (as->operation == 2 && as->array_quantity > 0)  {
			struct session_entry *entries = payload;

			for (i=0; i<as->array_quantity; i++){
				struct session_entry *current = &entries[i];
				inet_ntop(AF_INET6, &(current->ipv6.local.address), str, INET6_ADDRSTRLEN);
				printf("Session local: %s:%d, %s#%d\n",
						inet_ntoa(current->ipv4.local.address), ntohs(current->ipv4.local.pi.port),
						str, ntohs(current->ipv6.local.pi.port));
				inet_ntop(AF_INET6, &(current->ipv6.remote.address), str, INET6_ADDRSTRLEN);
				printf("Session remote: %s:%d, %s#%d\n",
						inet_ntoa(current->ipv4.remote.address), ntohs(current->ipv4.remote.pi.port),
						str, ntohs(current->ipv6.remote.pi.port));
			}
		}
	break;
	case 2:
		if (as->operation == 0 || as->operation == 2) {
			printf("Result: %s\n", (unsigned char *) payload);
		}
	break;
	case 3:
		if (as->operation == 0 || as->operation == 2) {
			printf("Result: %s\n", (unsigned char *) payload);
		}
	break;
	case 4:
			printf("Result: %s\n", (unsigned char *) payload);
	break;
	case 5:
			printf("Result: %s\n", (unsigned char *) payload);
	break;
	default:
			printf("Parameter Error\n");
	}

    return 0;
}

int netlink_comm(struct manconf_struct ms){

    struct nl_sock *nls;
    int ret;

    nls = nl_socket_alloc();
    if (!nls) {
        printf("bad nl_socket_alloc\n");
        return EXIT_FAILURE;
    }
    nl_socket_disable_seq_check(nls);
    nl_socket_modify_cb(nls, NL_CB_MSG_IN , NL_CB_CUSTOM, kernel_response, NULL);
    ret = nl_connect(nls, NETLINK_USERSOCK);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
        nl_socket_free(nls);
        return EXIT_FAILURE;
    }
    nl_socket_add_memberships(nls, RTNLGRP_LINK, 0);
    ret = nl_send_simple(nls, MSG_TYPE_NAT64, 0,&(ms), sizeof(ms));
    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        nl_close(nls);
        nl_socket_free(nls);
        return EXIT_FAILURE;
    } else {
        printf("sent %d bytes\n", ret);
    }

    ret = nl_recvmsgs_default(nls);
   if (ret < 0) {
        nl_perror(ret, "nl_recvmsgs_default");
    }
    nl_close(nls);
    nl_socket_free(nls);

    return EXIT_SUCCESS;
}

int validateIPv4(char *ipaddr, struct in_addr *addr)
{
   if ( inet_pton(AF_INET, ipaddr, addr) < 1  ){
		printf("Error: Invalid IPv4 address net: %s\n", ipaddr);
		exit(-1);
	}
	
	return (EXIT_SUCCESS);
}

int validateIPv6(char *ipaddr, struct in6_addr *addr)
{
   if ( inet_pton(AF_INET6, ipaddr, addr) < 1  ){
		printf("Error: Invalid IPv6 address net: %s\n", ipaddr);
		exit(-1);
	}
	
	return (EXIT_SUCCESS);
}

/*
   The main function.
   Notice how now the only function call needed to process
   all command-line options and arguments nicely
   is argp_parse.
*/
int main (int argc, char **argv)
{
  struct arguments arguments;
  struct manconf_struct ms;

	char *ipv6_check_addr; 
	char *ipv6_check_maskbits; 
	char *ipv4_pool_addr_first_str, *ipv4_pool_addr_last_str;
    unsigned char addr_maskbits;
	struct in_addr ipv4_pool_addr_first, ipv4_pool_addr_last, network_addr;      // To validate IP addresses
    char str[INET_ADDRSTRLEN];; // To print ipv4 pool range

 /* Set argument defaults */

  arguments.dir6 = "";
  arguments.dir4 = "";
  arguments.pref = "";
  arguments.first = "";
  arguments.last = "";
  arguments.remote6 = "";
  arguments.remote4 = "";
  arguments.local6 = "";
  arguments.local4 = "";
  arguments.verbose = 0;
  arguments.mode = -1;
  arguments.op = -1;
  arguments.l4_protocol = -1;
  arguments.estatica = -1;
  arguments.l3_protocol = -1;
  arguments.submode = 0;

  /* Where the magic happens */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  switch(arguments.mode) {
	case 0:
	  ms.mode = arguments.mode;
	  ms.operation = arguments.op;
	  switch(arguments.op) {
		case 2:
			if (arguments.l4_protocol != -1) {
				ms.us.rs.protocol = arguments.l4_protocol;
			} else {
				printf("Missing protocol.\n");
				exit(-1);
			}
		break;
		default:
	 		printf("Nothing to see here bib.");
	  }
	break;
	case 1:
	  ms.mode = arguments.mode;
	  ms.operation = arguments.op;
	  switch(arguments.op) {
		case 0:
			i = 0;
  			pch = strtok (arguments.local4,"#");
  			while (pch != NULL) {
				if (i == 0){
					validateIPv4(arguments.local4, &i4addrf);
					ms.us.rs.ipv4_src_address = i4addrf;
				}
				if (i == 1){
   					ms.us.rs.ipv4_src_port_or_id = htons(atoi(pch));
				}
    			pch = strtok (NULL, "#");
				i++;
  			}

			i = 0;
  			pch = strtok (arguments.remote4,"#");
  			while (pch != NULL) {
				if (i == 0){
					validateIPv4(arguments.remote4, &i4addrf1);
					ms.us.rs.ipv4_dst_address = i4addrf1;
				}
				if (i == 1){
   					ms.us.rs.ipv4_dst_port_or_id = htons(atoi(pch));
				}
    			pch = strtok (NULL, "#");
				i++;
  			}

			i = 0;
  			pch = strtok (arguments.local6,"#");
  			while (pch != NULL) {
				if (i == 0){
					validateIPv6(arguments.local6, &i6addrf);
					ms.us.rs.ipv6_src_address = i6addrf;
				}
				if (i == 1){
   					ms.us.rs.ipv6_src_port_or_id = htons(atoi(pch));
				}
    			pch = strtok (NULL, "#");
					i++;
  				}

			i = 0;
  			pch = strtok (arguments.remote6,"#");
  			while (pch != NULL) {
				if (i == 0){
					validateIPv6(arguments.remote6, &i6addrf1);
					ms.us.rs.ipv6_dst_address = i6addrf1;
				}
				if (i == 1){
   					ms.us.rs.ipv6_dst_port_or_id = htons(atoi(pch));
				}
    			pch = strtok (NULL, "#");
				i++;
  			}

			if (arguments.l4_protocol != -1) {
				ms.us.rs.protocol = arguments.l4_protocol;
			} else {
				printf("Missing protocol.\n");
				exit(-1);
			}

		break;
		case 1:
			if( strcmp (arguments.local6, "") == 0 && strcmp (arguments.remote6,"") == 0  ){
				i = 0;
		  		pch = strtok (arguments.local4,"#");
		  		while (pch != NULL) {
					if (i == 0){
						validateIPv4(arguments.local4, &i4addrf);
						ms.us.rs.ipv4_src_address = i4addrf;
					}
					if (i == 1){
		   				ms.us.rs.ipv4_src_port_or_id = htons(atoi(pch));
					}
		    		pch = strtok (NULL, "#");
					i++;
		  		}
				i = 0;
		  		pch = strtok (arguments.remote4,"#");
		  		while (pch != NULL) {
					if (i == 0){
						validateIPv4(arguments.remote4, &i4addrf1);
						ms.us.rs.ipv4_dst_address = i4addrf1;
					}
					if (i == 1){
		   				ms.us.rs.ipv4_dst_port_or_id = htons(atoi(pch));
					}
		    		pch = strtok (NULL, "#");
					i++;
		  		}
				if (arguments.l4_protocol != -1) {
					ms.us.rs.protocol = arguments.l4_protocol + 2;
				} else {
					printf("Missing protocol.\n");
					exit(-1);
				}		
			} else if( strcmp (arguments.local4, "") == 0 && strcmp (arguments.remote4,"") == 0  ) {
				i = 0;
	  			pch = strtok (arguments.local6,"#");
	  			while (pch != NULL) {
					if (i == 0){
						validateIPv6(arguments.local6, &i6addrf);
						ms.us.rs.ipv6_src_address = i6addrf;
					}
					if (i == 1){
	   					ms.us.rs.ipv6_src_port_or_id = htons(atoi(pch));
					}
	    			pch = strtok (NULL, "#");
						i++;
	  			}
				i = 0;
	  			pch = strtok (arguments.remote6,"#");
	  			while (pch != NULL) {
					if (i == 0){
						validateIPv6(arguments.remote6, &i6addrf1);
						ms.us.rs.ipv6_dst_address = i6addrf1;
					}
					if (i == 1){
	   					ms.us.rs.ipv6_dst_port_or_id = htons(atoi(pch));
					}
	    			pch = strtok (NULL, "#");
					i++;
	  			}
				if (arguments.l4_protocol != -1) {
					ms.us.rs.protocol = arguments.l4_protocol + 1;
				} else {
					printf("Missing protocol.\n");
					exit(-1);
				}			
			}
		break;
		case 2:
			if (arguments.l4_protocol != -1) {
				ms.us.rs.protocol = arguments.l4_protocol;
			} else {
				printf("Missing protocol.\n");
				exit(-1);
			}
		break;
		default:
	 		printf("Nothing to see here session.");
	  }

	break;
	case 2:
	  ms.mode = arguments.mode;
	  ms.operation = arguments.op;
	  switch(arguments.op) {
		case 0:

			// Split prefix and netmask bits
		    ipv6_check_addr = strtok(arguments.pref, "/");
		    ipv6_check_maskbits = strtok(NULL, "/");

		    // Validate IPv6 addr
		    if ( convert_ipv6_addr(ipv6_check_addr, &i6addrf) != EXIT_FAILURE )	
		    {
		        printf("Error: Invalid IPv6 address net: %s\n", ipv6_check_addr);
		        exit(-1);
		    }
		    // Validate netmask bits
		    addr_maskbits = atoi(ipv6_check_maskbits);
		    if ( validate_ipv6_netmask_bits(addr_maskbits) != EXIT_FAILURE )
		    {
		        printf("Error: Bad IPv6 network mask bits value: %d\n", addr_maskbits);
		        exit(-1);
		    }

		    ipv6_pref_qty = 1; 
		    // Allocate memory for the array of prefixes.
		    ipv6_pref = (struct ipv6_prefixes **) malloc(ipv6_pref_qty * sizeof(struct ipv6_prefixes *));       

		    // Allocate memory for each IPv6 prefix
		    ipv6_pref[0] = (struct ipv6_prefixes *) malloc(sizeof(struct ipv6_prefixes));
		    ipv6_pref[0]->addr = (i6addrf);
		    ipv6_pref[0]->maskbits = addr_maskbits;

		    // Store prefixes in the config struct
		    ms.us.cs.ipv6_net_prefixes = ipv6_pref;
		    ms.us.cs.ipv6_net_prefixes_qty = ipv6_pref_qty;
		break;
		case 1:
		break;
		case 2:
		break;
		default:
	 		printf("Nothing to see here IPv6.");
	  }
	break;
	case 3:
	  ms.mode = arguments.mode;
	  ms.operation = arguments.op;
	  switch(arguments.op) {
		case 0:

	 		// Validate pool addresses range
			ipv4_pool_addr_first_str = arguments.first;
		    ipv4_pool_addr_last_str = arguments.last;
			if ( convert_ipv4_addr(ipv4_pool_addr_first_str, &ipv4_pool_addr_first) != EXIT_FAILURE )	// Validate ipv4 addr
			{
				printf("Error: Malformed ipv4_pool_range_first: %s\n", ipv4_pool_addr_first_str);
				exit(-1);
			}
			if ( convert_ipv4_addr(ipv4_pool_addr_last_str, &ipv4_pool_addr_last) != EXIT_FAILURE  )	// Validate ipv4 addr
			{
				printf("Error: Malformed ipv4_pool_range_last: %s\n", ipv4_pool_addr_last_str);
				exit(-1);
			}

			// Store values in config struct
			network_addr.s_addr = ipv4_pool_addr_first.s_addr & ipv4_pool_addr_last.s_addr;
 			inet_ntop(AF_INET, &(network_addr.s_addr), str, INET_ADDRSTRLEN);
			printf("\t\t- network_addr: %s\n", str);

			addr_maskbits = calc_netmask(ipv4_pool_addr_first.s_addr, ipv4_pool_addr_last.s_addr);


			if (  validate_ipv4_pool_range(&network_addr, addr_maskbits, &ipv4_pool_addr_first, &ipv4_pool_addr_last) == EXIT_FAILURE )		//Validate that: first < last
			 {
				printf("Error: Pool addresses badly defined.\n");
				 exit(-1);
			}


			ms.us.cs.ipv4_pool_net = network_addr;
        	ms.us.cs.ipv4_pool_net_mask_bits = addr_maskbits;
			printf("\t\t- Pool Network: %s/%d\n", str, addr_maskbits);


		    ms.us.cs.ipv4_pool_range_first = ipv4_pool_addr_first;
		    ms.us.cs.ipv4_pool_range_last = ipv4_pool_addr_last;
		    inet_ntop(AF_INET, &(ipv4_pool_addr_first.s_addr), str, INET_ADDRSTRLEN);
			printf("\t\t- First address: %s\n", str);
		    inet_ntop(AF_INET, &(ipv4_pool_addr_last.s_addr), str, INET_ADDRSTRLEN);
			printf("\t\t- Last address: %s\n", str);


		    // TODO: Handle multiple IPv6 prefixes.

		    // TODO: Add an ID to identify what config value you are setting.

		    // TODO: Add a new option to the parser in order to enforce OR not this policy:
		        /*  If the port s is in the Well-Known port range 0-1023, and the
		            NAT64 has an available port t in the same port range, then the
		            NAT64 SHOULD allocate the port t. If the NAT64 does not have a
		            port available in the same range, the NAT64 MAY assign a port t
		            from another range where it has an available port.
		            If the port s is in the range 1024-65535, and the NAT64 has an
		            available port t in the same port range, then the NAT64 SHOULD
		            allocate the port t. If the NAT64 does not have a port available
		            in the same range, the NAT64 MAY assign a port t from another
		            range where it has an available port.
		         * */

		break;
		case 1:
		break;
		case 2:
		break;
		default:
	 		printf("Nothing to see here IPv4.");
	  }
	break;

	case 4:
	  ms.mode = arguments.mode;
	  ms.operation = arguments.op;
		if( strcmp (arguments.hairpin, "on") == 0){
	 		printf("Hairpinning ON.\n");
			ms.us.cs.hairpinning_mode = 1;
		} else if( strcmp (arguments.hairpin, "off") == 0){
			 		printf("Hairpinning OFF.\n");
			ms.us.cs.hairpinning_mode = 0;
		} else {
 			printf("Nothing to see here, hair.");
			exit(-1);
		}
	break;
	case 5:
	 ms.mode = arguments.mode;
	 ms.submode = arguments.submode;

	 if (arguments.submode & PHR_MASK){
		ms.us.cc.packet_head_room = arguments.head;
	 }

	 if (arguments.submode & PTR_MASK){
		ms.us.cc.packet_tail_room = arguments.tail;
	 }

	 if(arguments.submode & IPV6_NEXTHOP_MASK){
		ms.us.cc.ipv6_nexthop_mtu = arguments.mtu6;
	 }

	 if(arguments.submode & IPV4_NEXTHOP_MASK){
		ms.us.cc.ipv4_nexthop_mtu = arguments.mtu4;
	 } 

	 if(arguments.submode & IPV4_TRAFFIC_MASK){
		ms.us.cc.ipv4_traffic_class = arguments.tclass4;
	 } 

 	 if(arguments.submode & OIPV6_MASK){
		if( strcmp (arguments.b1, "true") == 0 ){
			ms.us.cc.override_ipv6_traffic_class = true;
		 } else if( strcmp (arguments.b1, "false") == 0 ){
			ms.us.cc.override_ipv6_traffic_class = false;
		} else {
			exit(-1);
		}
	 } 

 	 if(arguments.submode & OIPV4_MASK){
		if( strcmp (arguments.b2, "true") == 0 ){
			ms.us.cc.override_ipv4_traffic_class = true;
		 } else if( strcmp (arguments.b2, "false") == 0 ){
			ms.us.cc.override_ipv4_traffic_class = false;
		} else {
			exit(-1);
		}
	 } 

 	if(arguments.submode & DF_ALWAYS_MASK){
		if( strcmp (arguments.b3, "true") == 0 ){
			ms.us.cc.df_always_set = true;
		 } else if( strcmp (arguments.b3, "false") == 0 ){
			ms.us.cc.df_always_set = false;
		} else {
			exit(-1);
		}
	 } 

 	if(arguments.submode & GEN_IPV4_MASK){
		if( strcmp (arguments.b4, "true") == 0 ){
			ms.us.cc.generate_ipv4_id = true;
		 } else if( strcmp (arguments.b4, "false") == 0 ){
			ms.us.cc.generate_ipv4_id = false;
		} else {
			exit(-1);
		}
	 } 

 	if(arguments.submode & IMP_MTU_FAIL_MASK){
		if( strcmp (arguments.b5, "true") == 0 ){
			ms.us.cc.improve_mtu_failure_rate = true;
		 } else if( strcmp (arguments.b5, "false") == 0 ){
			ms.us.cc.improve_mtu_failure_rate = false;
		} else {
			exit(-1);
		}
	 } 

	if(arguments.submode & MTU_PLATEAUS_MASK){
				cont = 0;
				mtus = (__u16*) malloc(cont * sizeof(*mtus));
		  		pch = strtok (arguments.mtus,",");
		  		while (pch != NULL) {
					cont++;
					mtutemp = (__u16*) realloc(mtus,cont * sizeof(__u16));
					if (mtutemp!=NULL) {
						   mtus=mtutemp;
						   mtus[cont-1]=atoi(pch);
						 }
		    		pch = strtok (NULL, ",");
		  		}

			mtup_count = cont;
			ms.us.cc.mtu_plateaus = mtus;
			ms.us.cc.mtu_plateau_count = mtup_count;
	 } 

	if(arguments.submode & ADDRESS_DEPENDENT_FILTER_MASK){
		if( strcmp (arguments.b6, "true") == 0 ){
			ms.us.cs.address_dependent_filtering = 1;
		 } else if( strcmp (arguments.b6, "false") == 0 ){
			ms.us.cs.address_dependent_filtering = 0;
		} else {
			exit(-1);
		}
	 } 

	if(arguments.submode & FILTER_INFO_MASK){
		if( strcmp (arguments.b7, "true") == 0 ){
			ms.us.cs.filter_informational_icmpv6 = 1;
		 } else if( strcmp (arguments.b7, "false") == 0 ){
			ms.us.cs.filter_informational_icmpv6 = 0;
		} else {
			exit(-1);
		}
	 }

	if(arguments.submode & DROP_TCP_MASK){
		if( strcmp (arguments.b8, "true") == 0 ){
			ms.us.cs.drop_externally_initiated_tcp_connections = 1;
		 } else if( strcmp (arguments.b8, "false") == 0 ){
			ms.us.cs.drop_externally_initiated_tcp_connections = 0;
		} else {
			exit(-1);
		}
	 }  

	break;
	default:
 		printf("Use --help or --usage to see the command list \n");
		exit(-1);
  }

//send to kernel
	netlink_comm(ms);

  return 0;
}
