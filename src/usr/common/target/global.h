#ifndef _JOOL_USR_GLOBAL_H
#define _JOOL_USR_GLOBAL_H

#include "common/config.h"
#include "usr/common/types.h"

/* Mega global */
#define OPTNAME_INAME			"instance-name"

/* Modes */
#define OPTNAME_GLOBAL			"global"
#define OPTNAME_POOL4			"pool4"
#define OPTNAME_BLACKLIST		"blacklist"
#define OPTNAME_RFC6791			"pool6791"
#define OPTNAME_EAMT			"eamt"
#define OPTNAME_BIB			"bib"
#define OPTNAME_SESSION			"session"
#define OPTNAME_PARSE_FILE		"file"
#define OPTNAME_JOOLD			"joold"
#define OPTNAME_INSTANCE		"instance"

/* Operations */
#define OPTNAME_DISPLAY			"display"
#define OPTNAME_COUNT			"count"
#define OPTNAME_ADD			"add"
#define OPTNAME_UPDATE			"update"
#define OPTNAME_REMOVE			"remove"
#define OPTNAME_FLUSH			"flush"
#define OPTNAME_ADVERTISE		"advertise"
#define OPTNAME_TEST			"test"
#define OPTNAME_ACK			"ack"

/* Normal flags */
#define OPTNAME_ENABLE			"enable"
#define OPTNAME_DISABLE			"disable"
#define OPTNAME_ZEROIZE_TC		"zeroize-traffic-class"
#define OPTNAME_OVERRIDE_TOS		"override-tos"
#define OPTNAME_TOS			"tos"
#define OPTNAME_MTU_PLATEAUS		"mtu-plateaus"
#define OPTNAME_POOL6			"pool6"

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
#define OPTNAME_MAX_SO			"maximum-simultaneous-opens"
#define OPTNAME_SRC_ICMP6E_BETTER	"source-icmpv6-errors-better"
#define OPTNAME_HANDLE_FIN_RCV_RST	"handle-rst-during-fin-rcv"
#define OPTNAME_F_ARGS			"f-args"
#define OPTNAME_BIB_LOGGING		"logging-bib"
#define OPTNAME_SESSION_LOGGING		"logging-session"

/* pool4 flags */
#define OPTNAME_MARK			"mark"
#define OPTNAME_MAX_ITERATIONS		"max-iterations"

/* Synchronization flags */
#define OPTNAME_SS_ENABLED		"ss-enabled"
#define OPTNAME_SS_FLUSH_ASAP		"ss-flush-asap"
#define OPTNAME_SS_FLUSH_DEADLINE	"ss-flush-deadline"
#define OPTNAME_SS_CAPACITY		"ss-capacity"
#define OPTNAME_SS_MAX_PAYLOAD		"ss-max-payload"

int global_display(char *iname, display_flags flags);
int global_update(char *iname, __u16 type, size_t size, void *data, bool force);


#endif /* _JOOL_USR_GLOBAL_H */
