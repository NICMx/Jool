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

#define log_info(text, ...)	log_informational(pr_info, text, ##__VA_ARGS__)
#define log_debug(text, ...)	log_informational(pr_debug, text, ##__VA_ARGS__)
#define log_warning(text, ...)	log_informational(pr_warning, text, ##__VA_ARGS__)
#define log_err(text, ...)		log_error(pr_err, text, ##__VA_ARGS__)

/**
 * Netlink.
 */
#define MSG_TYPE_GRAYBOX (0x10 + 5)
#define MSG_GRAYBOX    (0x11)

/**
 * Config.
 */
enum config_operation{
	/** The userspace app wants to print the stuff being requested. */
	OP_DISPLAY = (1 << 0),
	/* The userspace app wants to add something. */
	OP_ADD = (1 << 1),
	/* The userspace app wants to clear some table. */
	OP_FLUSH = (1 << 2),
};

enum config_mode {
	/** The current message is talking about the receiver module. */
	MODE_RECEIVER = (1 << 1),
	/** The current message is talking about the sender module. */
	MODE_SENDER = (1 << 2),
	/** The current message is talking about the "byte array module". */
	MODE_GENERAL = (1 << 0),
};

/**
 * @{
 * Allowed operations for the mode mentioned in the name.
 * eg. BIB_OPS = Allowed operations for BIB requests.
 */
#define SENDER_OPS (OP_ADD)
#define RECEIVER_OPS (OP_ADD | OP_FLUSH | OP_DISPLAY)
#define GENERAL_OPS (OP_ADD | OP_FLUSH | OP_DISPLAY)
/**
 * @}
 */

/**
 * @{
 * Allowed modes for the operation mentioned in the name.
 * eg. DISPLAY_MODES = Allowed modes for display operations.
 */
#define ADD_MODES (MODE_RECEIVER | MODE_SENDER | MODE_GENERAL)
#define FLUSH_MODES (MODE_RECEIVER | MODE_GENERAL)
#define DISPLAY_MODES (MODE_RECEIVER | MODE_GENERAL)
/**
 * @}
 */
struct request_hdr {
	/** Size of the message. Includes header (this one) and payload. */
	__u32 len;
	/** See "enum config_mode". */
	__u8 mode;
	/** See "enum config_operation". */
	__u8 operation;
};


#endif
