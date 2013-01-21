#ifndef _NF_NAT64_CONSTANTS_H
#define _NF_NAT64_CONSTANTS_H

/**
 * @file
 * General purpose #defines, intended to minimize use of numerical constants elsewhere in the code.
 */

#include <linux/icmp.h>

// -- Timeouts, defined by RFC 6146, section 4. --

/** Minimum allowable session lifetime for UDP bindings, in seconds. TODO: we don't use it yet. */
#define UDP_MIN_ (2 * 60)
/**
 * Defined in the RFC as the minimum allowable default value for the session lifetime of UDP bindings,
 * in seconds. We use it as the actual default value.
 */
#define UDP_DEFAULT_ (5 * 60)
/** Transitory connection idle timeout.
 *  In other words, the timeout of several states in the TCP state machine. In seconds.
 */
#define TCP_TRANS (4 * 60)
/** Established connection idle timeout.
 *  In other words, the timeout of several states in the TCP state machine. In seconds.
 */
#define TCP_EST (2 * 60 * 60)
/** Timeout of several types of new STEs created during the CLOSED state of the TCP state machine. */
#define TCP_INCOMING_SYN (6)
/** Default time interval fragments are allowed to arrive in. In seconds. TODO: we don't use it yet. */
#define FRAGMENT_MIN_ (2)
/** Default session lifetime for ICMP bindings, in seconds. */
#define ICMP_DEFAULT_ (1 * 60)

// -- ICMP constants missing from icmp.h and icmpv6.h. --

/** Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/** Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2


/* ICMP error messaging */
//      Types:
#define DESTINATION_UNREACHABLE	ICMP_DEST_UNREACH 
//      Codes:
#define HOST_UNREACHABLE        ICMP_HOST_UNREACH
#define ADDRESS_UNREACHABLE     ICMP_HOST_UNREACH
#define COMMUNICATION_ADMINISTRATIVELY_PROHIBITED   ICMP_PKT_FILTERED



#endif
