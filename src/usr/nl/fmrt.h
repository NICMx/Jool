#ifndef SRC_USR_NL_FMRT_H_
#define SRC_USR_NL_FMRT_H_

#include "common/config.h"
#include "usr/nl/core.h"

typedef struct jool_result (*joolnl_fmrt_foreach_cb)(
	struct mapping_rule const *fmr, void *args
);

struct jool_result joolnl_fmrt_foreach(
	struct joolnl_socket *sk,
	char const *iname,
	joolnl_fmrt_foreach_cb cb,
	void *args
);

struct jool_result joolnl_fmrt_add(
	struct joolnl_socket *sk,
	char const *iname,
	struct ipv6_prefix const *p6,
	struct ipv4_prefix const *p4,
	__u8 ea_bits_length
);

#endif /* SRC_USR_NL_FMRT_H_ */
