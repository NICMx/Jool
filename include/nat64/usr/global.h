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

/* SIIT-only flags */
#define OPTNAME_AMEND_UDP_CSUM		"amend-udp-checksum-zero"
#define OPTNAME_EAM_HAIRPIN_MODE	"eam-hairpin-mode"
#define OPTNAME_RANDOMIZE_RFC6791	"randomize-rfc6791-addresses"
#define OPTNAME_RFC6791V6_PREFIX	"rfc6791v6-prefix"

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
#define OPTNAME_HANDLE_FIN_RCV_RST	"handle-rst-during-fin-rcv"
#define OPTNAME_F_ARGS			"f-args"
#define OPTNAME_BIB_LOGGING		"logging-bib"
#define OPTNAME_SESSION_LOGGING		"logging-session"

/* Synchronization flags */
#define OPTNAME_SS_ENABLED		"ss-enabled"
#define OPTNAME_SS_FLUSH_ASAP		"ss-flush-asap"
#define OPTNAME_SS_FLUSH_DEADLINE	"ss-flush-deadline"
#define OPTNAME_SS_CAPACITY		"ss-capacity"
#define OPTNAME_SS_MAX_PAYLOAD		"ss-max-payload"

int global_display(bool csv);
int global_update(__u16 type, size_t size, void *data);


#endif /* _JOOL_USR_GLOBAL_H */
