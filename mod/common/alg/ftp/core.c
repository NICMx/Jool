#include "nat64/mod/common/alg/ftp/core.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/alg/ftp/parser.h"
#include "nat64/mod/common/alg/ftp/state.h"

/*
 * This is still an early WIP. Still not included:
 *
 * - If the packet has the URG flag set, the urgent pointer might need to be
 *   updated if the pointed data moved.
 * - Update sequence numbers.
 * - Some multiple FTP commands per packet while actually translating.
 * - The ALGS command (Section 11).
 * - Timeouts and NOOP (Section 12).
 * - Language negotiation.
 *   I'm drifting towards "Not monitor LANG negotiation" to minimize state,
 *   but it might be even more convoluted than the monitor option:
 *
 *       Note that Section 3.1 of [RFC2640] specifies new handling for spaces
 *       and the carriage return (CR) character in pathnames.  ALGs that do
 *       not block LANG negotiation SHOULD comply with the specified rules for
 *       path handling.  Implementers should especially note that the NUL
 *       (%x00) character is used as an escape whenever a CR character occurs
 *       in a pathname.
 *
 *
 * I don't know why I'm supposed to worry about this:
 *
 * - if a language is negotiated, text transmitted
 *   by the client or the server MUST be assumed to be encoded in UTF-8
 *   [RFC3629] rather than be limited to 7-bit ASCII.
 *   (The ALG doesn't ever seem to care about encoding.)
 *
 *
 * Stuff that needs to be present in the user documentation:
 *
 * - "set-and-forget" policy is not recommended.
 * - The ALG only works when the server is listening in the default FTP port.
 *   (should this be configurable?)
 */

/*
 * If the packet is fragmented, we'll just have to hope for the best.
 * SIIT can't band fragments together, so it can't even know if a subsequent
 * fragment contains FTP data or not.
 * FTP control connections always yield small packets anyway, so this shouldn't
 * be a problem in normal operation.
 *
 * RFC 6384 is completely silent on the topic of fragments.
 */
static bool pkt_is_fragmented(struct packet *in)
{

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

static void xlat_epsv_into_pasv(struct packet *in)
{
	if (net_prt && net_ptr != 2)
		refuse_to_client(522, "Network protocol not supported");
	if (net_prt == "ALL")
		refuse_to_client(504, "Command not implemented for that parameter");

	pasv();
}

static void xlat_227_into_229(struct packet *in)
{
	struct in_addr tmp = { .s_addr = pkt_ip4_hdr(in)->saddr };

	if (!addr4_equals(response->addr, &tmp))
		refuse_to_client(425, "Can't open data connection");

	/* 229 Entering Extended Passive Mode (|||60691|) */
}

static verdict xlat_ftp_64(struct packet *in)
{
	struct ftp_control_channel_parser parser;
	char buffer[128];
	enum ftp_client_code code;
	int error;

	error = ftpparser_init(&parser, in->skb);
	if (error)
		return VERDICT_DROP;

	while (ftpparser_next(&parser, buffer) != -ENOENT) {
		code = ftpparser_get_client_code(buffer);
		switch (code) {
		case FTP_AUTH:
			ftpstate_client_sent_auth(in);
			break;
		case FTP_EPSV:
			if (config_xlat_epsv_as_pasv())
				xlat_epsv_into_pasv(in);
			break;
		case FTP_EPRT:
			xlat_eprt_into_port(in);
			break;
		}
	}

	ftpparser_destroy(&parser);
	return VERDICT_CONTINUE;
}

/* client to server */
verdict ftp_64(struct packet *in)
{
	if (!config_xlat_ftp()
			|| pkt_is_fragmented(in)
			|| !pkt_dst_is_ftp(in)
			|| ftpstate_is_transparent_mode(in))
		return VERDICT_CONTINUE;

	return xlat_ftp_64(in);
}

static verdict xlat_ftp_46(struct packet *in)
{
	struct ftp_control_channel_parser parser;
	char buffer[128];
	enum ftp_server_code code;
	int error;

	error = ftpparser_init(&parser, in->skb);
	if (error)
		return VERDICT_DROP;

	while (ftpparser_next(&parser, buffer) != -ENOENT) {
		code = ftpparser_get_server_code(buffer);
		switch (code) {
		case FTP_227:
			/*
			 * TODO is 227 possible as a response to something
			 * other than EPSV?
			 */
			if (config_xlat_epsv_as_pasv())
				xlat_227_into_229(in);
			break;
		case FTP_REJECT:
			ftpstate_server_denied(in);
			break;
		}
	}

	ftpstate_server_finished(in);

	ftpparser_destroy(&parser);
	return VERDICT_CONTINUE;
}

/* server to client */
verdict ftp_46(struct packet *in)
{
	if (!config_xlat_ftp()
			|| pkt_is_fragmented(in)
			|| !pkt_src_is_ftp(in)
			|| ftpstate_is_transparent_mode(in))
		return VERDICT_CONTINUE;

	return xlat_ftp_46(in);
}

