#ifndef _NF_NAT64_CONSTANTS_H
#define _NF_NAT64_CONSTANTS_H

/**
 * @file
 * General purpose #defines, intended to minimize use of numerical constants elsewhere in the code.
 */


// -- ICMP constants missing from icmp.h and icmpv6.h. --

/** Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/** Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2


#endif
