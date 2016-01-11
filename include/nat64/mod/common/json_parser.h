#ifndef JSON_PARSER_H_
#define JSON_PARSER_H_

#include <linux/netlink.h>
#include "nat64/mod/common/config.h"

int jparser_init(void);
void jparser_destroy(void);

int jparser_handle(struct request_hdr *jool_hdr, __u8 *request);

#endif /* JSON_PARSER_H_ */
