#include "nf_nat64_tuple_handling.h"
#include "nf_nat64_bib_session.h"
#include "nf_nat64_rfc6052.h"
#include "xt_nat64_module_conf.h"

/*
 * This procedure performs packet filtering and
 * updates BIBs and STs.
 */
bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol, 
        struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
    struct nat64_bib_entry *bib;
    struct nat64_st_entry *session;
    struct tcphdr *tcph = tcp_hdr(skb);
    //struct icmphdr *icmph = icmp_hdr(skb);
    bool res;
    int i;
    res = false;

    if (l3protocol == NFPROTO_IPV4) {
        pr_debug("NAT64: FNU - IPV4");
        /*
         * Query the STs for any records
         * If there's no active session for the specified 
         * connection, the packet should be dropped
         */
        switch (l4protocol) {
            case IPPROTO_TCP:
                //Query TCP ST
                //pr_debug("NAT64: TCP protocol not currently supported.");

                bib = nat64_bib_ipv4_lookup((*inner).dst.u3.in.s_addr, 
                        inner->dst.u.tcp.port, 
                        IPPROTO_TCP);
                if (!bib) {
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.tcp.port);				
                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }

                pr_debug("NAT64: TCP protocol for IPv4 "
                        "finished properly.");
                res = true;
                break;
            case IPPROTO_UDP:
                //Query UDP BIB and ST

                bib = nat64_bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        (inner->dst.u.udp.port),
                        IPPROTO_UDP);
                if (!bib) {
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.udp.port);				
                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }

                pr_debug("NAT64: UDP protocol for IPv4 "
                        "finished properly.");
                res = true;
                break;
            case IPPROTO_ICMP:
                //Query ICMP ST
                bib = nat64_bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        (inner->src.u.icmp.id),
                        IPPROTO_ICMPV6);

                if (!bib) {
                    pr_debug("No se pudo con T':%pI4.", &inner->dst.u3.in.s_addr);
                    pr_debug("Inner: %hu", ntohs(inner->src.u.icmp.id));
                    pr_warning("NAT64: IPv4 - BIB is missing.");
                    return res;
                }

                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.icmp.id);				

                if (!session) {
                    pr_warning("NAT64: IPv4 - session entry is "
                            "missing.");
                    return res;
                }
                res = true;
                break;
            case IPPROTO_ICMPV6:
                //Query ICMPV6 ST
                pr_debug("NAT64: ICMPv6 protocol not "
                        "currently supported.");
                break;
            default:
                //Drop packet
                pr_debug("NAT64: layer 4 protocol not "
                        "currently supported.");
                break;
        }
        goto end;
    } else if (l3protocol == NFPROTO_IPV6) {
        pr_debug("NAT64: FNU - IPV6");	
        // FIXME: Return true if it is not H&H. A special return code 
        // will have to be added as a param in the future to handle it.
        res = false;
        nat64_clean_expired_sessions(&expiry_queue,i);
        for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
        	nat64_clean_expired_sessions(&expiry_base[i].queue, i);

        switch (l4protocol) {
            case IPPROTO_TCP:
                /*
                 * FIXME: Finish TCP session handling
                 */
                pr_debug("NAT64: FNU - TCP");

                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.tcp.port, IPPROTO_TCP);
                if(bib) {
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                            inner->dst.u.tcp.port);
                    if(session) {
                        nat64_tcp6_fsm(session, tcph);
                    }else{
                        pr_debug("Create a session entry, no sesion.");
                        session = nat64_session_create_tcp(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    //prefix_len), 
                                ipv6_pref_len), 
                                inner->dst.u.tcp.port, 
                                TCP_TRANS);
                    }
                } else if (tcph->syn) {
                    pr_debug("Create a new BIB and Session entry syn.");
                    bib = nat64_bib_session_create_tcp(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                        inner->src.u.tcp.port, 
                        inner->dst.u.tcp.port, 
                        l4protocol, TCP_TRANS);

                    session = list_entry(bib->sessions.next, struct nat64_st_entry, list);
                    session->state = V6_SYN_RCV;
                }
                res = true;
                break;
            case IPPROTO_UDP:
                pr_debug("NAT64: FNU - UDP");
                /*
                 * Verify if there's any binding for the src 
                 * address by querying the UDP BIB. If there's a
                 * binding, verify if there's a connection to the 
                 * specified destination by querying the UDP ST.
                 * 
                 * In case these records are missing, they 
                 * should be created.
                 */
                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.udp.port,
                        IPPROTO_UDP);
                if (bib) {
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->dst.u.udp.port);
                    if (session) {
                        nat64_session_renew(session, UDP_DEFAULT);
                    } else {
                        session = nat64_session_create(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    ipv6_pref_len), 
                                inner->dst.u.udp.port, 
                                UDP_DEFAULT);
                    }
                } else {
                    pr_debug("Create a new BIB and Session entry.");
                    bib = nat64_bib_session_create(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->src.u.udp.port, 
                            inner->dst.u.udp.port, 
                            l4protocol, UDP_DEFAULT);
                }
                res = true;
                break;
            case IPPROTO_ICMP:
                //Query ICMP ST
                pr_debug("NAT64: ICMP protocol not currently "
                        "supported.");
                break;
            case IPPROTO_ICMPV6:
                //Query ICMPV6 ST
                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), 
                        inner->src.u.icmp.id, IPPROTO_ICMP);
                if(bib) {
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                //prefix_len), 
                            ipv6_pref_len), 
                            inner->src.u.icmp.id);
                    if(session) {
                        nat64_session_renew(session, ICMP_DEFAULT);
                    }else {
                        session = nat64_session_create_icmp(bib, 
                                &(inner->dst.u3.in6), 
                                nat64_extract_ipv4(
                                    inner->dst.u3.in6, 
                                    ipv6_pref_len), 
                                inner->src.u.icmp.id, 
                                ICMP_DEFAULT);
                    }
                } else {
                    pr_debug("Create a new BIB and Session entry.");
                    bib = nat64_bib_session_create_icmp(
                            &(inner->src.u3.in6), 
                            &(inner->dst.u3.in6), 
                            nat64_extract_ipv4(
                                inner->dst.u3.in6, 
                                ipv6_pref_len), 
                            inner->src.u.icmp.id, 
                            inner->src.u.icmp.id, 
                            l4protocol, ICMP_DEFAULT);
                }
                res = true;
                /*pr_debug("NAT64: ICMPv6 protocol not currently "*/
                /*"supported.");*/
                break;
            default:
                //Drop packet
                pr_debug("NAT64: layer 4 protocol not currently "
                        "supported.");
                break;
        }
        goto end;
    }

    return res;
end: 
    if (res) 
        pr_debug("NAT64: Updating and Filtering stage went OK.");
    else 
        pr_debug("NAT64: Updating and Filtering stage FAILED.");
    return res;
}

struct nf_conntrack_tuple * nat64_determine_outgoing_tuple(
        u_int8_t l3protocol, u_int8_t l4protocol, struct sk_buff *skb, 
        struct nf_conntrack_tuple * inner,
        struct nf_conntrack_tuple * outgoing)
{
    struct nat64_bib_entry *bib;
    struct nat64_st_entry *session;
    struct in_addr * temp_addr;
    struct in6_addr * temp6_addr;
    struct tcphdr *th;

    outgoing = kmalloc(sizeof(struct nf_conntrack_tuple), GFP_ATOMIC);
    memset(outgoing, 0, sizeof(struct nf_conntrack_tuple));

    if (!outgoing) {
        pr_warning("NAT64: There's not enough memory for the outgoing tuple.");
        return NULL;
    }

    /*
     * Get the tuple out of the BIB and ST entries.
     */
    if (l3protocol == NFPROTO_IPV4) {
        temp6_addr = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
        memset(temp6_addr, 0, sizeof(struct in6_addr));

        if (!temp6_addr) {
            pr_warning("NAT64: There's not enough memory to do a procedure "
                    "to get the outgoing tuple.");
            return NULL;
        }
        switch (l4protocol) {
            case IPPROTO_TCP:

                //pr_debug("NAT64: TCP protocol not"
                //		" currently supported.");
                bib = nat64_bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->dst.u.tcp.port, 
                        IPPROTO_TCP);
                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }
                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.tcp.port);				
                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }
                th=tcp_hdr(skb);
                nat64_tcp4_fsm(session, th);

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.tcp.port = 
                    session->embedded6_port; // y port
                outgoing->dst.u.tcp.port = 
                    session->remote6_port; // x port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr

                pr_debug("NAT64: TCP outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                        &(outgoing->src.u3.in6), ntohs(outgoing->src.u.tcp.port), 
                        &(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.tcp.port) ); 
                break;
            case IPPROTO_UDP:
                bib = nat64_bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->dst.u.udp.port,  
                        IPPROTO_UDP);
                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }

                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.udp.port);				
                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.udp.port = 
                    session->embedded6_port; // y port
                outgoing->dst.u.udp.port = 
                    session->remote6_port; // x port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr

                pr_debug("NAT64: UDP outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                        &(outgoing->src.u3.in6), ntohs(outgoing->src.u.udp.port), 
                        &(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.udp.port) );  //Rob

                break;
            case IPPROTO_ICMP:
                bib = nat64_bib_ipv4_lookup(inner->dst.u3.in.s_addr, 
                        inner->src.u.icmp.id,  
                        IPPROTO_ICMPV6);

                if (!bib) {
                    pr_warning("NAT64: The bib entry of the outgoing"
                            " tuple wasn't found.");
                    return NULL;
                }

                session = nat64_session_ipv4_lookup(bib, 
                        inner->src.u3.in.s_addr, 
                        inner->src.u.icmp.id);				

                if (!session) {
                    pr_debug("NAT64: The session table entry of"
                            " the outgoing tuple wasn't"
                            " found.");
                    return NULL;
                }

                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;

                // Ports
                outgoing->src.u.icmp.id = 
                    session->embedded6_port; // y port

                // SRC IP
                outgoing->src.u3.in6 = 
                    session->embedded6_addr; // Y' addr

                // DST IP
                outgoing->dst.u3.in6 = 
                    session->remote6_addr; // X' addr


                break;
            case IPPROTO_ICMPV6:
                pr_debug("NAT64: ICMPv6 protocol not currently "
                        "supported.");
                break;
            default:
                pr_debug("NAT64: layer 4 protocol not currently "
                        "supported.");
                break;
        }
    } else if (l3protocol == NFPROTO_IPV6) {
        temp_addr = kmalloc(sizeof(struct in_addr), GFP_ATOMIC);
        memset(temp_addr, 0, sizeof(struct in_addr));

        if (!temp_addr) {
            pr_warning("NAT64: There's not enough memory to do a "
                    "procedure to get the outgoing tuple.");
            return NULL;
        }
        /*
         * Get the tuple out of the BIB and ST entries.
         */

        switch (l4protocol) {
            case IPPROTO_TCP:
                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.tcp.port, 
                        IPPROTO_TCP);
                break;
            case IPPROTO_UDP:
                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.udp.port, 
                        IPPROTO_UDP);
                break;
            case IPPROTO_ICMPV6:
                bib = nat64_bib_ipv6_lookup(&(inner->src.u3.in6), inner->src.u.icmp.id, 
                        IPPROTO_ICMPV6);
                break;
            default:
                pr_debug("NAT64: no hay BIB, lol, jk?");
                break;
        }

        if (bib) {
            //session = session_ipv4_lookup(bib, 
            //			nat64_extract_ipv4(inner->dst.u3.in6, ipv6_pref_len),
            //			inner->dst.u.udp.port);

            switch (l4protocol) {
                case IPPROTO_TCP:
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.tcp.port);
                            ipv6_pref_len), inner->dst.u.tcp.port);
                    break;
                case IPPROTO_UDP:
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.udp.port);
                            ipv6_pref_len), inner->dst.u.udp.port);
                    break;
                case IPPROTO_ICMPV6:
                    session = nat64_session_ipv4_lookup(bib, 
                            nat64_extract_ipv4(inner->dst.u3.in6, 
                                //prefix_len), inner->dst.u.udp.port);
                            ipv6_pref_len), inner->src.u.icmp.id);
                    break;
                default:
                    pr_debug("NAT64: no hay sesion, lol, jk?");
                    break;
            }

            if (session) {
                // Obtain the data of the tuple.
                outgoing->src.l3num = (u_int16_t)l3protocol;
                switch (l4protocol) {
                    case IPPROTO_TCP:
                        //pr_debug("NAT64: TCP protocol not "
                        //		"currently supported.");

                        // Ports
                        outgoing->src.u.tcp.port = bib->local4_port;
                        outgoing->dst.u.tcp.port = session->remote4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        pr_debug("NAT64: TCP outgoing tuple: %pI4 : %d --> %pI4 : %d", 
                                &(outgoing->src.u3.in), ntohs(outgoing->src.u.tcp.port), 
                                &(outgoing->dst.u3.in), ntohs(outgoing->dst.u.tcp.port));
                        break;
                    case IPPROTO_UDP:
                        // Ports
                        outgoing->src.u.udp.port = 
                            bib->local4_port;
                        outgoing->dst.u.udp.port = 
                            session->remote4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        pr_debug("NAT64: UDP outgoing tuple: %pI4 : %d --> %pI4 : %d", 
                                &(outgoing->src.u3.in), ntohs(outgoing->src.u.udp.port), 
                                &(outgoing->dst.u3.in), ntohs(outgoing->dst.u.udp.port) );
                        break;
                    case IPPROTO_ICMP:
                        pr_debug("NAT64: ICMP protocol not currently supported.");
                        break;
                    case IPPROTO_ICMPV6:
                        // Ports
                        outgoing->src.u.icmp.id = 
                            bib->local4_port;

                        // SRC IP
                        outgoing->src.u3.ip = bib->local4_addr;
                        temp_addr->s_addr = bib->local4_addr;
                        outgoing->src.u3.in = *(temp_addr);

                        // DST IP
                        outgoing->dst.u3.ip = session->remote4_addr;
                        temp_addr->s_addr = session->remote4_addr;
                        outgoing->dst.u3.in = *(temp_addr);

                        break;
                    default:
                        pr_debug("NAT64: layer 4 protocol not currently supported.");
                        break;
                }
            } else {
                pr_debug("The session wasn't found.");
                goto error;
            }
        } else {
            pr_debug("The BIB wasn't found.");
            goto error;
        }
    }

    return outgoing;

error:
    return NULL;
}

bool nat64_got_hairpin(u_int8_t l3protocol, struct nf_conntrack_tuple * outgoing) {
	bool res;	  	
	struct in_addr sa1;
	struct in_addr sa2;
	//~ in4_pton(FIRST_ADDRESS, -1, (u8 *)&sa1, '\x0', NULL);
	//~ in4_pton(LAST_ADDRESS, -1, (u8 *)&sa2, '\x0', NULL);
	//~ sa1.s_addr = ipv4_addr; // FIXME: Rob. Think changing 'ipv4_addr' datatype by: struct in_addr
	sa1 = ipv4_pool_range_first;
	sa2 = ipv4_pool_range_last;
	res = false;
	if (l3protocol == NFPROTO_IPV6) { 
		if (ntohl(outgoing->dst.u3.in.s_addr) >= ntohl(sa1.s_addr) && ntohl(outgoing->dst.u3.in.s_addr) <= ntohl(sa2.s_addr)) {
			res = true;
		} 
 	} 
	return res;
}

struct nf_conntrack_tuple * nat64_hairpinning_and_handling(u_int8_t l4protocol, 
		struct nf_conntrack_tuple * inner,
		struct nf_conntrack_tuple * outgoing) {
	struct nat64_bib_entry *bib;
	struct nat64_bib_entry *bib2;
	struct nat64_st_entry *session;
	struct nat64_st_entry *session2;
	
			switch (l4protocol) {
				case IPPROTO_TCP:
					bib = nat64_bib_ipv4_lookup(
						outgoing->dst.u3.in.s_addr,
						outgoing->dst.u.tcp.port,
						IPPROTO_TCP);
					bib2 = nat64_bib_ipv6_lookup(&inner->src.u3.in6, inner->src.u.tcp.port, IPPROTO_TCP);
					if (bib && bib2) {
						session = nat64_session_ipv4_hairpin_lookup(bib, 
							outgoing->dst.u3.in.s_addr, 
							outgoing->dst.u.tcp.port);	
						session2 = nat64_session_ipv4_lookup(bib2, 
							outgoing->dst.u3.in.s_addr, 
							outgoing->dst.u.tcp.port);			
						if (!session || !session2) {
							pr_warning("NAT64 hairpin: IPv4 - session entry is "
									"missing.");
						} else {
							outgoing->src.u3.in6 =  session2->embedded6_addr;  
							outgoing->src.u.tcp.port =  session2->local4_port; 
							outgoing->dst.u.tcp.port = session->remote6_port; 
							outgoing->dst.u3.in6 = session->remote6_addr; 
							pr_debug("NAT64: TCP hairpin outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                       						 &(outgoing->src.u3.in6), ntohs(outgoing->src.u.tcp.port), 
                        					 &(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.tcp.port) ); 
						}
					} else {
						pr_warning("NAT64 hairpin: IPv4 - BIB is missing.");			
					}
					break;
				case IPPROTO_UDP:
					bib = nat64_bib_ipv4_lookup(
						outgoing->dst.u3.in.s_addr,
						outgoing->dst.u.udp.port,
						IPPROTO_UDP);
                	bib2 = nat64_bib_ipv6_lookup(&inner->src.u3.in6, inner->src.u.udp.port, IPPROTO_UDP);
					if (bib && bib2) {
						session = nat64_session_ipv4_hairpin_lookup(bib, 
							nat64_extract_ipv4(inner->dst.u3.in6, ipv6_pref_len), 
							inner->dst.u.udp.port);	
						session2 = nat64_session_ipv4_lookup(bib2, 
							outgoing->dst.u3.in.s_addr, 
							outgoing->dst.u.udp.port);					
						if (!session || !session2) {
							pr_warning("NAT64 hairpin: IPv4 - session entry is "
									"missing.");
						} else {
							outgoing->src.u3.in6 = session2->embedded6_addr; 
							outgoing->src.u.udp.port = session2->local4_port; 
							outgoing->dst.u.udp.port = session->remote6_port; 
							outgoing->dst.u3.in6 = session->remote6_addr; 

							pr_debug("NAT64: UDP hairpin outgoing tuple: %pI6c : %d --> %pI6c : %d", 
                        					&(outgoing->src.u3.in6), ntohs(outgoing->src.u.udp.port), 
                        					&(outgoing->dst.u3.in6), ntohs(outgoing->dst.u.udp.port) );  //Rob
						}
					} else {
						pr_warning("NAT64 hairpin: IPv4 - BIB is missing.");			
					}
					break;
				default:
					break;
			}
			return outgoing;
}
