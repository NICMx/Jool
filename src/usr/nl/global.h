#ifndef SRC_USR_NL_GLOBAL_H_
#define SRC_USR_NL_GLOBAL_H_

#include "usr/util/cJSON.h"
#include "usr/nl/core.h"

struct joolnl_global_meta;

struct jool_result joolnl_global_query(
	struct joolnl_socket *sk,
	char const *iname,
	struct globals *out
);

struct jool_result joolnl_global_update(
	struct joolnl_socket *sk,
	char const *iname,
	struct joolnl_global_meta const *meta,
	char const *value,
	bool force
);

struct jool_result joolnl_global_packetize_json(
	struct nl_msg *msg,
	struct joolnl_global_meta const *meta,
	cJSON *json
);

void joolnl_global_print(
	struct joolnl_global_meta const *meta,
	struct globals *config,
	bool csv
);

struct joolnl_global_meta const *joolnl_global_meta_first(void);
struct joolnl_global_meta const *joolnl_global_meta_next(
		struct joolnl_global_meta const *meta);
struct joolnl_global_meta const *joolnl_global_meta_last(void);
unsigned int joolnl_global_meta_count(void);

#define joolnl_global_foreach(pos) 					\
	for (								\
		pos = joolnl_global_meta_first();			\
		pos <= joolnl_global_meta_last();			\
		pos = joolnl_global_meta_next(pos)			\
	)

char const *joolnl_global_meta_name(struct joolnl_global_meta const *meta);
xlator_type joolnl_global_meta_xt(struct joolnl_global_meta const *meta);
char const *joolnl_global_meta_values(struct joolnl_global_meta const *meta);

#endif /* SRC_USR_NL_GLOBAL_H_ */
