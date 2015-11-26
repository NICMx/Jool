
static bool pkt_dst_is_ftp(struct pkt *in)
{
	return (pkt_l4_proto(in) == L4PROTO_TCP)
			&& (pkt_tcp_hdr(in)->dest == cpu_to_be16(21));
}

static bool pkt_src_is_ftp(struct pkt *in)
{
	return (pkt_l4_proto(in) == L4PROTO_TCP)
			&& (pkt_tcp_hdr(in)->source == cpu_to_be16(21));
}

/*
 * Find and extract IAC DO and IAC WILL from the packet.
 * Respectively answer WONT and DONT to everything.
 * Then forward the rest of the packet, if anything remains (which will require
 * major packet mangling).
 *
 * This is so unbelievably convoluted I can't believe it's actually being
 * requested by an actual RFC.
 *
 * Quoting RFC6384:
 *
 *     Telnet option negotiation attempts by either the
 *     client or the server, except for those allowed by [RFC1123], MUST be
 *     refused by the FTP ALG without relaying those attempts.  For the
 *     purpose of Telnet option negotiation, an FTP ALG MUST follow the
 *     behavior of an FTP server as specified in [RFC1123], Section
 *     4.1.2.12.
 *
 * It seems to be saying the same thing twice: Ban all options.
 * It doesn't make much sense because the "exceptions" listed by RFC 1123 seem
 * to be SYNCH and IP, both of which are actually commands, not options...
 *
 * Why the hell don't RFCs use pseudocode+english instead of just english...
 *
 * And why does the ALG need to do any of this anyway?
 * Neither the client nor the server are going to ask for options, and if they
 * do, the other end will refuse. And if they aren't refused, then this isn't
 * conformant FTP in the first place. I shouldn't be held responsible for
 * brain-dead implementations failing.
 *
 *     This avoids the situation where the client and the server
 *     negotiate Telnet options that are unimplemented by the FTP ALG.
 *
 * How is this a justification? Aside from this requirement, the ALG is
 * completely option-agnostic.
 *
 * What the fuck. I'm actually considering not doing any of this bullshit.
 */
static bool is_negociating_opts(struct pkt *in)
{
	return false;
}

static verdict refuse(void)
{
	/* Enviar WONT, probablemente. */
	return VERDICT_DROP;
}

static verdict xlat_epsv_into_pasv()
{
	if (net_prt && net_ptr != 2)
		return refuse_to_client(522, "Network protocol not supported");
	if (net_prt == "ALL")
		return refuse_to_client(504, "Command not implemented for that parameter");

	return pasv();
}

static verdict xlat_227_into_229(struct packet *in)
{
	if (!addr4_equals(response->addr, pkt_ip4_hdr(in)->saddr))
		return refuse_to_client(425, "Can't open data connection");

	/* 229 Entering Extended Passive Mode (|||60691|) */
}

static verdict server_transparent_mode()
{
	/*
	 * first time: if code is 4xx or 5xx, cancel transparent mode.
	 * Otherwise remain transparent forever.
	 */

	/*
	 * In transparent mode, the ALG MUST continue to
	 * adjust sequence numbers if it was doing so before entering
	 * transparent mode as the result of the AUTH command.
	 */
}

/*
 * If the packet is fragmented, we'll just have to hope for the best.
 * SIIT can't band fragments together, so it can't even know if a subsequent
 * fragment contains FTP data or not.
 * FTP control connections always yield small packets anyway, so this shouldn't
 * be a problem in normal operation.
 *
 * RFC 6384 is completely silent on the topic of fragments.
 */
static bool pkt_is_fragmented(in)
{

}

/* client to server */
verdict ftp_64(struct pkt *in)
{
	if (!config_xlat_ftp())
		return VERDICT_CONTINUE;

	if (pkt_is_fragmented(in))
		return VERDICT_CONTINUE;

	if (!pkt_dst_is_ftp(in))
		return VERDICT_CONTINUE;

	if (is_negociating_opts(in))
		return refuse();

	/* TODO is auth a non 1123 op? */
	if (is_auth(in))
		return go_into_transparent_mode(in);

	if (config_xlat_epsv_as_pasv() && is_epsv(in))
		return xlat_epsv_into_pasv(in);

	if (is_eprt(in))
		/* statefulness-dependant */
		return xlat_eprt_into_port();

	return VERDICT_CONTINUE;
}

/* server to client */
verdict ftp_46(struct pkt *in)
{
	if (!config_xlat_ftp())
		return VERDICT_CONTINUE;

	if (pkt_is_fragmented(in))
		return VERDICT_CONTINUE;

	if (!pkt_src_is_ftp(in))
		return VERDICT_CONTINUE;

	if (is_transparent_mode(in))
		return server_transparent_mode(in);

	if (is_negociating_opts(in))
		return refuse();

	/* TODO is 227 possible as a response to something other than EPSV? */
	if (config_xlat_epsv_as_pasv() && code_is_227())
		return xlat_227_into_229(in);

	return VERDICT_CONTINUE;
}

