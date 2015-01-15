#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

#include <linux/types.h>
#ifdef __KERNEL__
	#include <linux/in.h>
	#include <linux/in6.h>
#else
	#include <arpa/inet.h>
#endif


#define MODULE_NAME "graybox"

/**
 * Logging utilities, meant for standarization of error messages.
 */
#ifdef __KERNEL__
	#define log_error(func, text, ...) func("%s (%s): " text "\n", \
			MODULE_NAME, __func__, ##__VA_ARGS__)
	#define log_informational(func, text, ...) func(text "\n", ##__VA_ARGS__)
#else
	#define log_error(func, text, ...) printf(text "\n", ##__VA_ARGS__)
	#define log_informational(func, text, ...) printf(text "\n", ##__VA_ARGS__)
#endif

#define log_info(text, ...)	log_informational(pr_debug, text, ##__VA_ARGS__)
#define log_debug(text, ...)	log_informational(pr_debug, text, ##__VA_ARGS__)
#define log_warning(text, ...)	log_informational(pr_warning, text, ##__VA_ARGS__)
#define log_err(text, ...)		log_error(pr_err, text, ##__VA_ARGS__)

/**
 * Netlink.
 */
#define MSG_TYPE_FRAGS (0x10 + 3)
#define MSG_SENDPKT    (0x11)

/**
 * Config.
 */

enum operations {
	/** The userspace app wants to send a packet to the sender module. */
	OP_SENDER = (1 << 0),
	/** The userspace app wants to send a packet to the receiver module. */
	OP_RECEIVER = (1 << 1),
	/** .*/
	OP_FLUSH_DB = (1 << 2),
};

struct request_hdr {
	/** Size of the message. Includes header (this one) and payload. */
	__u32 len;
	/** See "enum config_mode". */
	__u8 mode;
	/** See "enum config_operation". */
	__u8 operation;
};


#endif
