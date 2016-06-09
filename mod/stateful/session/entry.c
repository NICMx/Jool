#include "nat64/mod/stateful/session/entry.h"

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/bib/db.h"

/** Cache for struct session_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

int session_init(void)
{
	entry_cache = kmem_cache_create("jool_session_entries",
			sizeof(struct session_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Session entry cache.");
		return -ENOMEM;
	}

	return 0;
}

void session_destroy(void)
{
	kmem_cache_destroy(entry_cache);
}

struct session_entry *session_create(const struct ipv6_transport_addr *src6,
		const struct ipv6_transport_addr *dst6,
		const struct ipv4_transport_addr *src4,
		const struct ipv4_transport_addr *dst4,
		l4_protocol l4_proto,
		struct bib_entry *bib)
{
	struct session_entry tmp = {
			.src6 = *src6,
			.dst6 = *dst6,
			.src4 = *src4,
			.dst4 = *dst4,
			.l4_proto = l4_proto,
			.state = 0,
			.update_time = jiffies,
			.bib = bib,
			.expirer = NULL,
	};
	return session_clone(&tmp);
}

/**
 * Creates a copy of "session".
 *
 * The copy will not be part of the database regardless of session's state.
 */
struct session_entry *session_clone(struct session_entry *session)
{
	struct session_entry *result;

	result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	memcpy(result, session, sizeof(*session));
	INIT_LIST_HEAD(&result->list_hook);
	if (session->bib)
		bibentry_get_db(session->bib);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);
	kref_init(&result->refs);

	return result;
}

void session_get(struct session_entry *session)
{
	kref_get(&session->refs);
}

static void session_release(struct kref *ref)
{
	struct session_entry *session;
	session = container_of(ref, struct session_entry, refs);

	if (session->bib)
		bibentry_put_db(session->bib);
	kmem_cache_free(entry_cache, session);
}

/**
 * session_put - unregister your reference towards @session. Will destroy
 * @session if there are no more references.
 * @must_die: If @session is expected to die during this put, send true.
 * Will drop a stack trace in the kernel logs if it doesn't die.
 * true = "entry MUST die." false = "entry might or might not die."
 *
 * You might want to do this outside of spinlocks, because it can cascade into
 * removing @session's BIB entry from its database, and that can be somewhat
 * expensive.
 */
void session_put(struct session_entry *session, bool must_die)
{
	bool dead = kref_put(&session->refs, session_release);
	WARN(must_die && !dead, "Session entry did not die!");
}

bool session_equals(const struct session_entry *s1,
		const struct session_entry *s2)
{
	return taddr6_equals(&s1->src6, &s2->src6)
			&& taddr6_equals(&s1->dst6, &s2->dst6)
			&& taddr4_equals(&s1->src4, &s2->src4)
			&& taddr4_equals(&s1->dst4, &s2->dst4)
			&& (s1->l4_proto == s2->l4_proto);
}

void session_log(const struct session_entry *session, const char *action)
{
	struct timeval tval;
	struct tm t;

	do_gettimeofday(&tval);
	time_to_tm(tval.tv_sec, 0, &t);
	log_info("%ld/%d/%d %d:%d:%d (GMT) - %s %pI6c#%u|%pI6c#%u|%pI4#%u|%pI4#%u|%s",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec, action,
			&session->src6.l3, session->src6.l4,
			&session->dst6.l3, session->dst6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4,
			l4proto_to_string(session->l4_proto));
}
