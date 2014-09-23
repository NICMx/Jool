
/** Cache for struct session_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

static void session_release(struct kref *ref)
{
	struct session_entry *session;
	session = container_of(ref, struct session_entry, refcounter);

	if (session->bib)
		bib_return(session->bib);
	kmem_cache_free(entry_cache, session);
}

static int session_init(void)
{
	entry_cache = kmem_cache_create("jool_session_entries", sizeof(struct session_entry),
			0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Session entry cache.");
		return -ENOMEM;
	}

	return 0;
}

static void session_destroy(void)
{
	kmem_cache_destroy(entry_cache);
}

int session_return(struct session_entry *session)
{
	return kref_put(&session->refcounter, session_release);
}

void session_get(struct session_entry *session)
{
	kref_get(&session->refcounter);
}

struct session_entry *session_clone(struct session_entry *session)
{
	struct session_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	memcpy(result, session, sizeof(*session));
	kref_init(&result->refcounter);
	INIT_LIST_HEAD(&result->expire_list_hook);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	if (session->bib)
		bib_get(session->bib);

	return result;
}

struct session_entry *session_create(const struct ipv6_transport_addr *remote6,
		const struct ipv6_transport_addr *local6,
		const struct ipv4_transport_addr *local4,
		const struct ipv4_transport_addr *remote4,
		l4_protocol l4_proto, struct bib_entry *bib)
{
	struct session_entry tmp = {
			.remote6 = *remote6,
			.local6 = *local6,
			.local4 = *local4,
			.remote4 = *remote4,
			.update_time = jiffies,
			.bib = bib,
			.l4_proto = l4_proto,
			.state = 0,
			.expirer = NULL,
	};
	return session_clone(&tmp);
}
