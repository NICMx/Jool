#include "nat64/usr/joold/hdr.h"

#include "nat64/common/config.h"
#include "nat64/common/xlat.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/types.h"
#include "errno.h"

/* TODO (duplicate code) this is the same as in nl_handler2. */

static int validate_magic(struct request_hdr *hdr, char *sender)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	/* Well, the sender does not understand the protocol. */
	log_err("%s sent a message that lacks the Jool magic text.", sender);
	return -EINVAL;
}

static int validate_stateness(struct request_hdr *hdr, char *sender)
{
	switch (hdr->type) {
	case 'n':
		return 0;
	case 's':
		log_err("I got a message from '%s SIIT', but SIIT lacks joold...",
				sender);
		return -EINVAL;
	}

	log_err("%s sent a packet with an unknown stateness: '%c'",
			sender, hdr->type);
	return -EINVAL;
}

static int validate_version(struct request_hdr *hdr, char *sender)
{
	if (xlat_version() == hdr->version)
		return 0;

	log_err("Version mismatch. %s's version is %u.%u.%u.%u,\n"
			"but my version is %u.%u.%u.%u.\n"
			"Please update %s.",
			sender,
			hdr->version >> 24, (hdr->version >> 16) & 0xFFU,
			(hdr->version >> 8) & 0xFFU, hdr->version & 0xFFU,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr->version) ? sender : "me");
	return -EINVAL;
}

int validate_header(void *data, size_t data_len, char *sender)
{
	struct request_hdr *hdr;
	int error;

	if (data_len < sizeof(struct request_hdr)) {
		log_err("Message from %s is smaller than Jool's header.",
				sender);
		return -EINVAL;
	}

	hdr = data;

	error = validate_magic(hdr, sender);
	if (error)
		return error;
	error = validate_stateness(hdr, sender);
	if (error)
		return error;
	error = validate_version(hdr, sender);
	if (error)
		return error;

	return 0;
}
