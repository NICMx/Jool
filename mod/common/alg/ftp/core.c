#include "nat64/mod/common/alg/ftp/core.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/alg/ftp/parser/ctrl_channel.h"
#include "nat64/mod/common/alg/ftp/state/db.h"

/*
 * This is still a WIP. Still not included:
 *
 * - TCP header mangling (urgent pointer and sequence numbers)
 * - The state machine.
 * - NOOP (Section 12) (this needs to belong to the state machine.)
 *
 *
 * I don't know why I'm supposed to worry about this:
 *
 * - "if a language is negotiated, text transmitted
 *   by the client or the server MUST be assumed to be encoded in UTF-8
 *   [RFC3629] rather than be limited to 7-bit ASCII."
 *   (UTF-8 contains 7-bit ASCII, so the parser doesn't have to expect different
 *   strings.)
*  - "Note that Section 3.1 of [RFC2640] specifies new handling for spaces
 *   and the carriage return (CR) character in pathnames.  ALGs that do
 *   not block LANG negotiation SHOULD comply with the specified rules for
 *   path handling.  Implementers should especially note that the NUL
 *   (%x00) character is used as an escape whenever a CR character occurs
 *   in a pathname."
 *   (I never need to parse pathnames. Not that it would be troublesome anyway,
 *   since RFC2640.3.1 prevents them from containing CRLF.)
 *
 *
 * Stuff that needs to be present in the user documentation:
 *
 * - "set and forget" policy is not recommended.
 * - The ALG only works when the server is listening in the default FTP port.
 *   (should this be configurable?)
 * - The ALG is _stateful_. Even in SIIT mode.
 * - The ALG assumes the client is IPv6 and the server is IPv4.
 *
 *
 * Stuff that baffles me, currently:
 *
 * - Section 12 seems unfinished.
 *   I think I'm going to have to replicate the NAT64 logic regarding the TCP
 *   state machine here. Why? because SIIT doesn't have it and needs to drop
 *   the FTP sessions after a teardown TCP handshake + TCP TRANS + data channels
 *   expired.
 *   Also, it seems I'm going to have to send keepalives as NOOPs (assuming no
 *   transparent mode) or TCP probes.
 * - The ALG is FUCKING _STATEFUL_. STATEFUL. EVEN IN SIIT MODE.
 *   Perhaps I should move it to userspace.
 */

static DEFINE_SPINLOCK(lock);

static bool pkt_dst_is_ftp(struct packet *in)
{
	return (pkt_l4_proto(in) == L4PROTO_TCP)
			&& (pkt_tcp_hdr(in)->dest == cpu_to_be16(21));
}

static bool pkt_src_is_ftp(struct packet *in)
{
	return (pkt_l4_proto(in) == L4PROTO_TCP)
			&& (pkt_tcp_hdr(in)->source == cpu_to_be16(21));
}

static void update_ctrl_channel_timeout(struct packet *in)
{
	/* TODO */
}

static enum ftpxlat_action sm64(struct packet *in, struct ftp_state *state)
{
	struct ftp_ctrl_channel_parser parser;
	struct ftp_client_msg token;
	enum ftpxlat_action action = FTPXLAT_DO_NOTHING;

	/* TODO result code? */
	ftpparser_init(&parser, in);

	while (ftpparser_client_nextline(&parser, &token) != -ENOENT) {
		switch (token.code) {
		case FTP_AUTH:
			action = ftpsm_client_sent_auth(state);
			break;
		case FTP_EPSV:
			action = ftpsm_client_sent_epsv(state);
			break;
		case FTP_EPRT:
			action = ftpsm_client_sent_eprt(state);
			break;
		case FTP_ALGS:
			action = ftpsm_client_sent_algs(state, &token);
			break;
		case FTP_CLIENT_UNRECOGNIZED:
			/*
			 * TODO A list of actions is probably more appropriate.
			 */
			action = FTPXLAT_DO_NOTHING;
			break;
		}
	}

	ftpparser_destroy(&parser);

	return action;
}

static verdict handle_action64(enum ftpxlat_action action)
{
	/* TODO */
	return VERDICT_CONTINUE;
}

/* client to server */
verdict ftp_64(struct packet *in)
{
	struct ftp_state *state;
	enum ftpxlat_action action;

	if (!config_xlat_ftp())
		return VERDICT_CONTINUE;
	/*
	 * If the packet is fragmented, we'll just have to hope for the best.
	 * SIIT can't band fragments together, so it can't even know if a
	 * subsequent fragment contains FTP data or not.
	 * FTP control connections always yield small packets anyway, so this
	 * shouldn't be a problem in normal operation.
	 *
	 * RFC 6384 is completely silent on the topic of fragments.
	 */
	if (is_fragmented_ipv6(pkt_frag_hdr(in)))
		return VERDICT_CONTINUE;
	if (!pkt_dst_is_ftp(in)) {
		update_ctrl_channel_timeout(in);
		return VERDICT_CONTINUE;
	}

	spin_lock_bh(&lock);

	state = ftpdb_get_or_create(in);
	if (!state) {
		spin_unlock_bh(&lock);
		return VERDICT_DROP;
	}

	/* TODO the line parsing can be pushed out of the spinlock. */
	action = ftpsm_is_transparent_mode(state)
			? FTPXLAT_DO_NOTHING
			: sm64(in, state);

	spin_unlock_bh(&lock);

	return handle_action64(action);
}

static enum ftpxlat_action sm46(struct packet *in, struct ftp_state *state)
{
	struct ftp_ctrl_channel_parser parser;
	struct ftp_server_msg token;
	enum ftpxlat_action action = FTPXLAT_DO_NOTHING;

	ftpparser_init(&parser, in);

	while (ftpparser_server_nextline(&parser, &token) != -ENOENT) {
		switch (token.code) {
		case FTP_227:
			action = ftpsm_server_sent_227(state);
			break;
		case FTP_REJECT:
			action = ftpsm_server_denied(state);
			break;
		case FTP_SERVER_UNRECOGNIZED:
			action = FTPXLAT_DO_NOTHING;
			break;
		}
	}

	ftpparser_destroy(&parser);

	return action;
}

static verdict handle_action46(enum ftpxlat_action action)
{
	/* TODO */
	return VERDICT_CONTINUE;
}

/* server to client */
verdict ftp_46(struct packet *in)
{
	struct ftp_state *state;
	enum ftpxlat_action action;

	if (!config_xlat_ftp())
		return VERDICT_CONTINUE;
	if (is_fragmented_ipv4(pkt_ip4_hdr(in)))
		return VERDICT_CONTINUE;
	if (!pkt_src_is_ftp(in)) {
		update_ctrl_channel_timeout(in);
		return VERDICT_CONTINUE;
	}

	spin_lock_bh(&lock);

	state = ftpdb_get(in);
	if (!state) {
		spin_unlock_bh(&lock);
		return VERDICT_DROP;
	}

	action = ftpsm_is_transparent_mode(state)
			? FTPXLAT_DO_NOTHING
			: sm46(in, state);

	spin_unlock_bh(&lock);

	return handle_action46(action);
}
