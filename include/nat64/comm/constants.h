#ifndef _NF_NAT64_CONSTANTS_H
#define _NF_NAT64_CONSTANTS_H

/**
 * @file
 * General purpose #defines, intended to minimize use of numerical constants elsewhere in the code.
 *
 * @author Roberto Aceves
 * @author Ramiro Nava
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */


/**
 * Step the module will be injected in within Netfilter's prerouting hook.
 * (After defragmentation, before Conntrack).
 */
#define NF_PRI_NAT64 -500

/* -- Timeouts, defined by RFC 6146, section 4. */

/**
 * Minimum allowable session lifetime for UDP bindings, in seconds.
 */
#define UDP_MIN (2 * 60)
/**
 * Defined in the RFC as the minimum allowable default value for the session lifetime of UDP bindings,
 * in seconds. We use it as the actual default value.
 */
#define UDP_DEFAULT (5 * 60)
/**
 * Established connection idle timeout (in seconds).
 * In other words, the tolerance time for established and healthy TCP sessions.
 * If a connection remains idle for longer than this, then we expect it to terminate soon.
 */
#define TCP_EST (2 * 60 * 60)
/**
 * Transitory connection idle timeout (in seconds).
 * In other words, the timeout of TCP sessions which are expected to terminate soon.
 */
#define TCP_TRANS (4 * 60)
/**
 * Timeout of TCP sessions being initialized (in seconds).
 * It's shorter by default since these are typical DoS attacks.
 */
#define TCP_INCOMING_SYN (6)
/** Default time interval fragments are allowed to arrive in. In milliseconds. */
#define FRAGMENT_MIN (2 * 1000)
/** Default session lifetime for ICMP bindings, in seconds. */
#define ICMP_DEFAULT (1 * 60)


/* -- Config defaults -- */
#define POOL6_DEF { "64:ff9b::/96" }

#define POOL4_DEF { "192.168.2.1", "192.168.2.2", "192.168.2.3", "192.168.2.4" }

#define FILT_DEF_ADDR_DEPENDENT_FILTERING false
#define FILT_DEF_FILTER_ICMPV6_INFO false
#define FILT_DEF_DROP_EXTERNAL_CONNECTIONS false

#define TRAN_DEF_RESET_TRAFFIC_CLASS false
#define TRAN_DEF_RESET_TOS false
#define TRAN_DEF_NEW_TOS 0
#define TRAN_DEF_DF_ALWAYS_ON true
#define TRAN_DEF_BUILD_IPV4_ID false
#define TRAN_DEF_LOWER_MTU_FAIL true
#define TRAN_DEF_MTU_PLATEAUS { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }
#define TRAN_DEF_MIN_IPV6_MTU 1280


/* -- IPv6 Pool -- */
#define POOL6_PREFIX_LENGTHS { 32, 40, 48, 56, 64, 96 }


/* -- ICMP constants missing from icmp.h and icmpv6.h. -- */

/** Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/** Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2


#endif
