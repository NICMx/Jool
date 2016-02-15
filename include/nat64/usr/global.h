#ifndef _JOOL_USR_GLOBAL_H
#define _JOOL_USR_GLOBAL_H

#include "nat64/common/config.h"

/* Normal flags */
#define OPTNAME_ENABLE			"enable"
#define OPTNAME_DISABLE			"disable"
#define OPTNAME_ZEROIZE_TC		"zeroize-traffic-class"
#define OPTNAME_OVERRIDE_TOS		"override-tos"
#define OPTNAME_PARSE_FILE		"parse-file"
#define OPTNAME_TOS			"tos"
#define OPTNAME_MTU_PLATEAUS		"mtu-plateaus"

/* Atomic fragment flags (deprecated) */
#define OPTNAME_ALLOW_ATOMIC_FRAGS	"allow-atomic-fragments"
#define OPTNAME_DF_ALWAYS_ON		"setDF"
#define OPTNAME_GENERATE_FH		"genFH"
#define OPTNAME_GENERATE_ID4		"genID"
#define OPTNAME_FIX_ILLEGAL_MTUS	"boostMTU"

/* SIIT-only flags */
#define OPTNAME_AMEND_UDP_CSUM		"amend-udp-checksum-zero"
#define OPTNAME_EAM_HAIRPIN_MODE	"eam-hairpin-mode"
#define OPTNAME_RANDOMIZE_RFC6791	"randomize-rfc6791-addresses"

/* NAT64-only flags */
#define OPTNAME_DROP_BY_ADDR		"address-dependent-filtering"
#define OPTNAME_DROP_ICMP6_INFO		"drop-icmpv6-info"
#define OPTNAME_DROP_EXTERNAL_TCP	"drop-externally-initiated-tcp"
#define OPTNAME_UDP_TIMEOUT		"udp-timeout"
#define OPTNAME_ICMP_TIMEOUT		"icmp-timeout"
#define OPTNAME_TCPEST_TIMEOUT		"tcp-est-timeout"
#define OPTNAME_TCPTRANS_TIMEOUT	"tcp-trans-timeout"
#define OPTNAME_FRAG_TIMEOUT		"fragment-arrival-timeout"
#define OPTNAME_MAX_SO			"maximum-simultaneous-opens"
#define OPTNAME_SRC_ICMP6E_BETTER	"source-icmpv6-errors-better"
#define OPTNAME_F_ARGS			"f-args"
#define OPTNAME_BIB_LOGGING		"logging-bib"
#define OPTNAME_SESSION_LOGGING		"logging-session"


/* Synchronization flags */
#define OPTNAME_SYNCH_ENABLE		"synch-enable"
#define OPTNAME_SYNCH_DISABLE		"synch-disable"
#define OPTNAME_SYNCH_MAX_SESSIONS	"synch-max-sessions"
#define OPTNAME_SYNCH_PERIOD		"synch-period"

int global_display(bool csv);
int global_update(__u16 type, size_t size, void *data);


#endif /* _JOOL_USR_GLOBAL_H */
