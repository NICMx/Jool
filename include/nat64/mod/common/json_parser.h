#ifndef JSON_PARSER_H_
#define JSON_PARSER_H_

#include <linux/netlink.h>
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/namespace.h"

int jparser_init(struct xlator **config);
void jparser_destroy(struct xlator *config);

int jparser_handle(struct xlator *config, struct request_hdr *jool_hdr,
		__u8 *request);

#endif /* JSON_PARSER_H_ */
