/*
 * NAT64 - Network Address Translator IPv6 to IPv4
 *
 * Authors:
 *	Representative NIC-Mx
 *	Ing. Gustavo Lozano <glozano@nic.mx>
 *	Ing. Jorge Cano
 *
 *	Representative ITESM
 *	Dr. Juan Arturo Nolazco	<jnolazco@itesm.mx>
 *	Ing. Martha Sordia <msordia@itesm.mx>
 *
 *	Students ITESM
 *	Juan Antonio Osorio <jaosorior@gmail.com>
 *	Luis Fernando Hinojosa <lf.hinojosa@gmail.com>
 *	David Valenzuela <david.valenzuela.88@gmail.com>
 *	Jose Vicente Ramirez <pepermz@gmail.com>
 *	Mario Gerardo Trevinho <mario_tc88@hotmail.com>
 *	Roberto Aceves <roberto.aceves@gmail.com>
 *	Miguel Alejandro González <maggonzz@gmail.com>
 *	Ramiro Nava <ramironava@gmail.com>
 *	Adrian González <bernardogzzf@gmail.com>
 *	Manuel Aude <dormam@gmail.com>
 *	Gabriel Chavez <gabrielchavez02@gmail.com>
 *	Alan Villela López <avillop@gmail.com>
 *	  
 *	  The rest of us, I propose include our names and order all alphabetically.
 *
 * Authors of the ip_data, checksum_adjust, checksum_remove, checksum_add
 * checksum_change, adjust_checksum_ipv6_to_ipv4, nat64_output_ipv4, 
 * adjust_checksum_ipv4_to_ipv6, nat64_xlate_ipv6_to_ipv4, nat64_alloc_skb,
 * nat64_xlate_ipv4_to_ipv6 functions that belong to the Ecdysis project:
 *	Jean-Philippe Dionne <jean-philippe.dionne@viagenie.ca>
 *	Simon Perreault <simon.perreault@viagenie.ca>
 *	Marc Blanchet <marc.blanchet@viagenie.ca>
 *
 *	Ecdysis <http://ecdysis.viagenie.ca/>
 *
 * The previous functions are found in the nf_nat64_main.c file of Ecdysis's 
 * NAT64 implementation.
 *
 * Please note: 
 * The function nat64_output_ipv4 was renamed as nat64_send_packet_ipv4 
 * under the kernel version that is inferior to 3.0 in this 
 * implementation. The function nat64_send_packet_ipv6 for both
 * kernel versions were based on this function.
 *
 * The functions nat64_xlate_ipv6_to_ipv4 and nat64_xlate_ipv4_to_ipv6 were
 * used as a point of reference to implement nat64_get_skb_from6to4 and
 * nat64_get_skb_from4to6, respectively. Furthermore, nat64_alloc_skb was
 * also used as a point of reference to implement nat64_get_skb.
 * 
 * Author of the nat64_extract_ipv4, nat64_allocate_hash, tcp_timeout_fsm,
 * tcp4_fsm, tcp6_fsm, bib_allocate_local4_port, bib_ipv6_lookup, bib_ipv4_lookup,
 * bib_create, bib_session_create, session_ipv4_lookup, session_renew,
 * session_create, clean_expired_sessions functions, nat64_ipv6_input:
 *	Julius Kriukas <julius.kriukas@gmail.com>
 * 
 * 	Linux NAT64 <http://ipv6.lt/nat64_en.php>
 *
 * The previous functions are found in the nat64_session.c and nat64_core.c
 * files of Julius Kriukas's Linux NAT64 implementation. Furthermore, these
 * functions used global variables which were added (with a comment indicating
 * their origin) in our xt_nat64.c file. The majority of these functions can 
 * be found in our nf_nat64_filtering_and_updating.h file. Not all of them are 
 * being used in this release version but are planned to be used in the future.
 * This is the case of the tcp4_fsm, tcp6_fsm, tcp_timeout_fsm and 
 * clean_expired_sessions functions and some of the global variables they use.
 * Part of our nat64_filtering_and_updating function was based on Julius's 
 * implementation of his nat64_ipv6_input function.
 *
 * NAT64 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NAT64 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with NAT64.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#ifndef _LINUX_NAT64_MODULE_CONF_H
#define _LINUX_NAT64_MODULE_CONF_H
/*
 * Communication with the NAT64 module (using netlink sockets).
 */

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES (Communication)
////////////////////////////////////////////////////////////////////////

#define MY_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary but is the same for kern/usr

////////////////////////////////////////////////////////////////////////
// DEFAULT VALUES (Configuration)
////////////////////////////////////////////////////////////////////////

// IPv6:
#define IPV6_DEF_PREFIX     "64:ff9b::"
#define IPV6_DEF_MASKBITS   96
//
#define IPV6_DEF_TCP_POOL_FIRST 1024		// FIXME: Rename to IPV6_DEF_TCP_PORTS_FIRST
#define IPV6_DEF_TCP_POOL_LAST  65535		// 		  Same thing
//
#define IPV6_DEF_UDP_POOL_FIRST 1024		// FIXME: Rename to IPV6_DEF_UDP_PORTS_FIRST
#define IPV6_DEF_UDP_POOL_LAST  65535		// 		  Same thing
// IPv4:
#define IPV4_DEF_NET        "192.168.2.0" 	// FIXME: Rename to IPV4_DEF_POOL_NET
#define IPV4_DEF_MASKBITS   24				// FIXME: Rename to IPV4_DEF_POOL_NET_MASK_BITS
//
#define IPV4_DEF_POOL_FIRST "192.168.2.1"
#define IPV4_DEF_POOL_LAST  "192.168.2.254"
//
#define IPV4_DEF_TCP_POOL_FIRST 1024		// FIXME: Rename to IPV4_DEF_TCP_PORTS_FIRST
#define IPV4_DEF_TCP_POOL_LAST  65535		// 		  Same thing
//
#define IPV4_DEF_UDP_POOL_FIRST 1024		// FIXME: Rename to IPV4_DEF_UDP_PORTS_FIRST
#define IPV4_DEF_UDP_POOL_LAST  65535		// 		  Same thing


////////////////////////////////////////////////////////////////////////
// STRUCTURES
////////////////////////////////////////////////////////////////////////

struct config_struct
{
    //// IPv4:
    struct in_addr ipv4_addr_net; 			// FIXME: Rename this to ipv4_pool_net
	unsigned char  ipv4_addr_net_mask_bits; // FIXME: Rename this to ipv4_pool_net_mask_bits
	struct in_addr ipv4_pool_range_first;
	struct in_addr ipv4_pool_range_last;
    //
    unsigned short ipv4_tcp_port_first;
    unsigned short ipv4_tcp_port_last;
    //
    unsigned short ipv4_udp_port_first;
    unsigned short ipv4_udp_port_last;
    
    //// IPv6:
    struct in6_addr ipv6_net_prefix;
	unsigned char   ipv6_net_mask_bits;
    //
	unsigned short  ipv6_tcp_port_range_first;
	unsigned short  ipv6_tcp_port_range_last;
	//
	unsigned short  ipv6_udp_port_range_first;
    unsigned short  ipv6_udp_port_range_last;   
};

////////////////////////////////////////////////////////////////////////
// VARIABLES
////////////////////////////////////////////////////////////////////////

//~ char *banner=
//~ "                                   ,----,                       \n"
//~ "         ,--.                    ,/   .`|                 ,--,  \n"
//~ "       ,--.'|   ,---,          ,`   .'  :               ,--.'|  \n"
//~ "   ,--,:  : |  '  .' \\       ;    ;     /  ,---.     ,--,  | :  \n"
//~ ",`--.'`|  ' : /  ;    '.   .'___,/    ,'  /     \\ ,---.'|  : '  \n"
//~ "|   :  :  | |:  :       \\  |    :     |  /    / ' ;   : |  | ;  \n"
//~ ":   |   \\ | ::  |   /\\   \\ ;    |.';  ; .    ' /  |   | : _' |  \n"
//~ "|   : '  '; ||  :  ' ;.   :`----'  |  |'    / ;   :   : |.'  |  \n"
//~ "'   ' ;.    ;|  |  ;/  \\   \\   '   :  ;|   :  \\   |   ' '  ; :  \n"
//~ "|   | | \\   |'  :  | \\  \\ ,'   |   |  ';   |   ``.\\   \\  .'. |  \n"
//~ "'   : |  ; .'|  |  '  '--'     '   :  |'   ;      \\`---`:  | '  \n"
//~ "|   | '`--'  |  :  :           ;   |.' '   |  .\\  |     '  ; |  \n"
//~ "'   : |      |  | ,'           '---'   |   :  ';  :     |  : ;  \n"
//~ ";   |.'      `--''                      \\   \\    /      '  ,/   \n"
//~ "'---'                                    `---`--`       '--'    \n";

char *banner=
"                                   ,----,                       \n"
"         ,--.                    ,/   .`|                 ,--,  \n"
"       ,--.'|   ,---,          ,`   .'**:               ,--.'|  \n"
"   ,--,:  :*|  '  .'*\\       ;    ;*****/  ,---.     ,--,  |#:  \n"
",`--.'`|  '*: /  ;****'.   .'___,/****,'  /     \\ ,---.'|  :#'  \n"
"|   :**:  |*|:  :*******\\  |    :*****|  /    /#' ;   :#|  |#;  \n"
":   |***\\ |*::  |***/\\***\\ ;    |.';**; .    '#/  |   |#: _'#|  \n"
"|   :*'**'; ||  :**' ;.***:`----'  |**|'    /#;   :   :#|.'##|  \n"
"'   '*;.****;|  |**;/  \\***\\   '   :**;|   :##\\   |   '#'##;#:  \n"
"|   |*| \\***|'  :**| \\  \\*,'   |   |**';   |###``.\\   \\##.'.#|  \n"
"'   :*|  ;*.'|  |**'  '--'     '   :**|'   ;######\\`---`:  |#'  \n"
"|   |*'`--'  |  :**:           ;   |.' '   |##.\\##|     '  ;#|  \n"
"'   :*|      |  |*,'           '---'   |   :##';##:     |  :#;  \n"
";   |.'      `--''                      \\   \\####/      '  ,/   \n"
"'---'                                    `---`--`       '--'    \n";


////////////////////////////////////////////////////////////////////////
// FUNCTION PROTOTYPES
////////////////////////////////////////////////////////////////////////

int init_nat_config(struct config_struct *cs);



#endif /* _LINUX_NAT64_MODULE_CONF_H */
