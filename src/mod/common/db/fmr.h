#ifndef SRC_MOD_COMMON_DB_FMR_H_
#define SRC_MOD_COMMON_DB_FMR_H_

#include "mod/common/types.h"

/* Forwarding Mapping Rules Table */
struct fmr_table;

struct fmr_table *fmrt_alloc(void);
void fmrt_get(struct fmr_table *fmrt);
void fmrt_put(struct fmr_table *fmrt);

int fmrt_find4(struct fmr_table *fmrt, __be32 addr, struct mapping_rule *fmr);
int fmrt_find6(struct fmr_table *fmrt, struct in6_addr const *addr,
		struct mapping_rule *fmr);

int fmrt_add(struct fmr_table *jool, struct mapping_rule *new);

typedef int (*fmr_foreach_cb)(struct mapping_rule const *, void *);
int fmrt_foreach(struct fmr_table *fmrt,
		fmr_foreach_cb cb, void *arg,
		struct ipv4_prefix *offset);

#endif /* SRC_MOD_COMMON_DB_FMR_H_ */
