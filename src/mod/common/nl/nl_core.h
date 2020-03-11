#ifndef SRC_MOD_COMMON_NL_CORE_H_
#define SRC_MOD_COMMON_NL_CORE_H_

#include <net/genetlink.h>

struct jool_response {
	struct genl_info *info;
	struct sk_buff *skb;
	struct joolnlhdr *hdr;
};

void nlcore_setup(struct genl_family *new_family,
		struct genl_multicast_group *new_group);
/* There's no nlcore_teardown; just destroy the family yourself. */
struct genl_family *nlcore_get_family(void);

int jresponse_init(struct jool_response *response, struct genl_info *info);
int jresponse_send(struct jool_response *response);
void jresponse_cleanup(struct jool_response *response);

void jresponse_enable_m(struct jool_response *response);
int jresponse_send_array(struct jool_response *response, int error);

int jresponse_send_simple(struct genl_info *info, int error);


#endif /* SRC_MOD_COMMON_NL_CORE_H_ */
