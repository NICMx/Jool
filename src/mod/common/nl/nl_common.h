#ifndef SRC_MOD_COMMON_NL_COMMON_H_
#define SRC_MOD_COMMON_NL_COMMON_H_

#include <net/genetlink.h>
#include "common/config.h"

struct jnl_state;

struct xlator;
struct jnl_state *jnls_create(struct xlator *jool);
void jnls_destroy(struct jnl_state *state);

/* -- Request handling -- */

/* For requests not associated with an instance. */
int __jnl_start(struct jnl_state **state, struct genl_info *info,
		xlator_type xt, bool require_net_admin);
/* For requests associated with an instance. */
int jnl_start(struct jnl_state **state, struct genl_info *info,
		xlator_type xt, bool require_net_admin);

/* If error != 0, replies error. Otherwise replies state->skb as is. */
int jnl_reply(struct jnl_state *state, int error);
/* If error > 0, replies state->skb with M. Otherwise jnl_reply(). */
int jnl_reply_array(struct jnl_state *state, int error);

/* Finish request handler without sending a response. */
void jnl_cancel(struct jnl_state *state);

/* -- Getters -- */
struct xlator *jnls_xlator(struct jnl_state *state);
struct sk_buff *jnls_skb(struct jnl_state *state);
struct joolnlhdr *jnls_jhdr(struct jnl_state *state);

/* -- Setters -- */
void jnls_set_xlator(struct jnl_state *state, struct xlator *jool);
void jnls_enable_m(struct jnl_state *state);

/* -- Validations -- */

int prefix4_validate(const struct ipv4_prefix *prefix, struct jnl_state *state);
int prefix6_validate(const struct ipv6_prefix *prefix, struct jnl_state *state);
int prefix4_validate_scope(struct ipv4_prefix *prefix, bool force,
		struct jnl_state *state);

/* -- Logging -- */
void __jnls_debug(struct xlator *jool, const char *fmt, ...)
		__attribute__((format(printf, 2, 3)));
#define jnls_debug(state, fmt, ...) \
	__jnls_debug(jnls_xlator(state), KERN_CONT fmt, ##__VA_ARGS__)
#define jnlx_debug(xlator, fmt, ...) \
	__jnls_debug(xlator, KERN_CONT fmt, ##__VA_ARGS__)

/**
 * "Your configuration cannot be applied, user."
 * log_warn_once() signals errors while processing packets. jnls_err() signals
 * errors while processing user requests.
 * I the code found a **programming** error, use WARN() or its variations
 * instead.
 */
int jnls_err(struct jnl_state *state, const char *fmt, ...)
		__attribute__((format(printf, 2, 3)));

#endif /* SRC_MOD_COMMON_NL_COMMON_H_ */
