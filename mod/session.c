
/********************************************
 * Structures and private variables.
 ********************************************/

/** Cache for struct session_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;


/********************************************
 * Private (helper) functions.
 ********************************************/

void session_release(struct kref *ref)
{
	struct session_entry *session;
	struct bib_entry *bib;

	session = container_of(ref, struct session_entry, refcounter);
	bib = session->bib;

	if (WARN(!bib, "The session entry I just removed had no BIB entry.")) {
		session_kfree(session);
		return;
	}
	bib_return(bib);
	session_kfree(session);
}

/*******************************
 * Public functions.
 *******************************/

int session_init(void)
{
	entry_cache = kmem_cache_create("jool_session_entries", sizeof(struct session_entry),
			0, 0, NULL);
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

int session_return(struct session_entry *session)
{
	return kref_put(&session->refcounter, session_release);
}

void session_get(struct session_entry *session)
{
	kref_get(&session->refcounter);
}

struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		l4_protocol l4_proto)
{
	struct session_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	kref_init(&result->refcounter);
	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->dying_time = 0;
	result->bib = NULL;
	INIT_LIST_HEAD(&result->expire_list_hook);
	result->l4_proto = l4_proto;
	result->state = 0;
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	return result;
}

void session_kfree(struct session_entry *session)
{
	kmem_cache_free(entry_cache, session);
}
