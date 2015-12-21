#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/alg/ftp/parser/tokenizer.h"
#include "nat64/mod/common/alg/ftp/state/db.h"
#include "nat64/mod/common/alg/ftp/sm.h"
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

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

int ftpalg_init(void)
{
	nf_defrag_ipv6_enable();
	nf_defrag_ipv4_enable();
	return 0;
}

void ftpalg_destroy(void)
{
	/* No code. */
}

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

/*
static int parse_pkt(struct packet *in, struct list_head *lines)
{
	struct ftp_parser parser;
	struct ftp_client_msg token;
	int error;

	INIT_LIST_HEAD(lines);

	parser_init(&parser, in->skb, pkt_payload_offset(in));

	while (!(error = client_next_token(&parser, &token))) {
		list_add_tail(&token->list_hook, lines);
	}

	switch (error) {
	case EOP:
		break;
	case -ETRUNCATED:
		break;
	}
}
*/

static verdict sm64(struct packet *in, struct ftp_state *state)
{
	struct ftp_parser parser;
	struct ftp_client_msg token;
	struct ftp_translated output;
	int error = 0;

	parser_init(&parser, in->skb, pkt_payload_offset(in));

	while (client_next_token(&parser, &token) != EOP) {
		switch (token.code) {
		case FTP_AUTH:
			error = ftpsm_client_sent_auth(&token, &output, state);
			break;
		case FTP_EPSV:
			error = ftpsm_client_sent_epsv(&token, &output, state);
			break;
		case FTP_EPRT:
			error = ftpsm_client_sent_eprt(&token, &output, state);
			break;
		case FTP_ALGS:
			error = ftpsm_client_sent_algs(&token, &output, state);
			break;
		case FTP_CLIENT_UNRECOGNIZED:
			error = ftpsm_client_sent_whatever(&token, &output);
			break;
		}

		if (error)
			return error;
	}

	parser_destroy(&parser);

	return 0;
}

/* client to server */
verdict ftp_64(struct packet *in)
{
	struct list_head lines;
	struct ftp_state *state;
	int error;

	if (!config_xlat_ftp())
		return VERDICT_CONTINUE;
	if (!pkt_dst_is_ftp(in)) {
		update_ctrl_channel_timeout(in);
		return VERDICT_CONTINUE;
	}

	error = parse_pkt(&lines);
	if (error) {
		log_debug("Packet parsing threw errcode %d.", error);
		return VERDICT_DROP;
	}

	spin_lock_bh(&lock);

	error = ftpdb_get_or_create(in, &state);
	if (error) {
		spin_unlock_bh(&lock);
		log_debug("The state DB threw errcode %d.", error);
		destroy_lines(&lines);
		return VERDICT_DROP;
	}

	if (ftpsm_is_transparent_mode(state)) {
		spin_unlock_bh(&lock);
		log_debug("Transparent mode.");
		destroy_lines(&lines);
		return VERDICT_CONTINUE;
	}

	error = sm64(in, state);
	if (error) {
		spin_unlock_bh(&lock);
		log_debug("The state machine threw errcode %d.", error);
		destroy_lines(&lines);
		return VERDICT_DROP;
	}

	spin_unlock_bh(&lock);

	error = xlat_pkt(&lines);
	if (error) {
		log_debug("The packet translation threw errcode %d.", error);
		destroy_lines(&lines);
		return VERDICT_DROP;
	}

	destroy_lines(&lines);
	return VERDICT_CONTINUE;
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
			action = ftpsm_server_sent_227(&token, state);
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
