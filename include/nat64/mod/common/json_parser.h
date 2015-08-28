/*
 * json_parser.h
 *
 *  Created on: Aug 18, 2015
 *      Author: dhernandez
 */

#ifndef JSON_PARSER_H_
#define JSON_PARSER_H_

#include <linux/netlink.h>
#include "nat64/mod/common/config.h"

int handle_json_file_config(struct nlmsghdr *nl_hdr,struct request_hdr *jool_hdr,__u8*request);

#endif /* JSON_PARSER_H_ */
