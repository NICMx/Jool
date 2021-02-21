#ifndef SRC_USR_ARGP_WARGP_GLOBAL_H_
#define SRC_USR_ARGP_WARGP_GLOBAL_H_

int handle_global_display(char *iname, int argc, char **argv, void const *arg);
void autocomplete_global_display(void const *args);

struct cmd_option *build_global_update_children(void);

#define WOPT_GLOBAL_MAPT_EUI6P(container) { \
		.xt = XT_MAPT, \
		.name = "end-user-ipv6-prefix", \
		.key = 'e', \
		.doc = "An IPv6 prefix unique to this CE, which will mask the nodes in its IPv4 island.", \
		.offset = offsetof(container, eui6p), \
		.type = &wt_prefix6, \
	}

#define WOPT_GLOBAL_MAPT_BMR(container) { \
		.xt = XT_MAPT, \
		.name = "bmr", \
		.key = 'b', \
		.doc = "The MAP domain's common configuration.", \
		.offset = offsetof(container, bmr), \
		.type = &wt_mapping_rule, \
	}

#endif /* SRC_USR_ARGP_WARGP_GLOBAL_H_ */
