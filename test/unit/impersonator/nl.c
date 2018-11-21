#include "mod/common/nl/nl_core.h"

int nlbuffer_init_request(struct nlcore_buffer *buffer, struct request_hdr *hdr,
		size_t capacity)
{
	return 0;
}

void nlbuffer_clean(struct nlcore_buffer *buffer)
{
	/* No code. */
}

int nlbuffer_write(struct nlcore_buffer *buffer, void const *data,
		size_t data_size)
{
	return 0;
}

int nlcore_send_multicast_message(struct net *ns, struct nlcore_buffer *buffer)
{
	return 0;
}
