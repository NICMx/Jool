#ifndef JSON_PARSER_H_
#define JSON_PARSER_H_

#include <linux/netlink.h>
#include "nat64/mod/common/config.h"

int handle_json_file_config(struct genl_info *info);

#endif /* JSON_PARSER_H_ */
