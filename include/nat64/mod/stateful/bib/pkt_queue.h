#ifndef _JOOL_MOD_PKT_QUEUE_H
#define _JOOL_MOD_PKT_QUEUE_H

/**
 * @file
 * As the name implies, this is just a small database of packets. These packets
 * are meant to be replied (in the form of an ICMP error) in the future.
 *
 * You can find the specifications for this in pages 28 and 29 (look up
 * "simultaneous open of TCP connections"), and 30 (look up "stored is sent
 * back") from RFC 6146.
 *
 * The RFC gets a little nonsensical here. These requirements seem to exist to
 * satisfy REQ-4 of RFC 5382
 * (http://ietf.10.n7.nabble.com/Simultaneous-connect-td222455.html), except
 * RFC 5382 wants us to cancel the ICMP error "If during this interval the NAT
 * receives and translates an outbound SYN for the connection", but this is not
 * very explicit in the specification of the V4_INIT state in RFC 6146. I mean
 * it's the only state where the session expiration triggers the ICMP message,
 * but it'd be nice to see confirmation that the stored packet can be forgotten
 * about.
 *
 * However, Marcelo Bagnulo's seemingly final comments really bend me over to
 * RFC 5382's behavior: "well, it may be sent inside an ICMP error message in
 * case the state times out and the V& SYN has not arrived."
 * (http://www.ietf.org/mail-archive/web/behave/current/msg08660.html)
 *
 * So... yeah, "Packet Storage". This is how I understand it:
 *
 * If a NAT64 receives a IPv4-UDP or a IPv4-ICMP packet for which it has no
 * state, it should reply a ICMP error because it doesn't know which IPv6 node
 * the packet should be forwarded to.
 *
 * If a NAT64 receives a IPv4-TCP packet for which it has no state, it should
 * not immediately reply a ICMP error because the IPv4 endpoint could be
 * attempting a "Simultaneous Open of TCP Connections"
 * (http://tools.ietf.org/html/rfc5128#section-3.4). What
 * happens is the NAT64 stores the packet for 6 seconds; if the IPv6 version of
 * the packet arrives, the NAT64 drops the original packet (the IPv4 node will
 * eventually realize this on its own by means of the handshake), otherwise a
 * ICMP error containing the original IPv4 packet is generated (because there's
 * no Simultaneous Open going on).
 */

#include "nat64/common/config.h"
#include "nat64/mod/common/packet.h"

struct pktqueue;

struct pktqueue_session {
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	bool src6_set;

	/*
	 * RFC 6146 also wants us to store src6 and dst6.
	 * I don't know why. They are never used for anything, ever.
	 *
	 * I mean, the logic is
	 *
	 * 1. Store packet A with session [src6,dst6,src4,dst4] = [a,b',c,b]
	 *    (where b' is the pool6 prefix + b)
	 *    Sometimes src6 is not available, so store [*,b',c,b].
	 * 2. If packet B matches A's session,
	 *        Forget packet A.
	 *        Continue from the V4 INIT state as normal.
	 * 3. If packet B hasn't arrived after 6 seconds,
	 *        Wrap A in an ICMP error and fetch it.
	 *        Forget packet A.
	 *
	 * The thing is [c,b] is already a primary key so a and b' are not
	 * needed to look up the session.
	 * I guess one could argue that b' and possibly a can be used to further
	 * make sure the correct session is hole punched. But what makes the v6
	 * addresses inferred during A's translation more valuable than those
	 * inferred during B's translation?
	 *
	 * - dst6 is deterministically mapped to dst4 unless pool6 changes. But
	 *   even if pool6 changes I don't see any reason why b talking through
	 *   the new b' should be a problem, so enforcing dst6 matching during
	 *   the second step seems futile.
	 * - Doesn't the same apply to src6 and pool4?
	 *
	 * It's not like a v4 attacker can use this to hijack a connection;
	 * We already know that B is directed to b specifically...
	 *
	 * Now, the thing about src6 is that it either does not exist (and
	 * therefore does not matter) or depends on a BIB entry.
	 * The latter case is hard to wrap one's head around. The RFC implies
	 * that this session should prevent the BIB entry from dying. By storing
	 * all SO sessions separately from the BIB, we are violating this.
	 * What are the consequences?
	 *
	 * 1. The BIB entry b1 dies while the SO session s0 is still waiting.
	 * 2. b1's src4 is reassigned to BIB entry b2 and now s0 contradicts b2.
	 *    We now have a slightly inconsistent BIB/session DB but since SO
	 *    sessions are not used during lookups
	 *
	 * WRONG. TODO
	 */
};

/**
 * Call during initialization for the remaining functions to work properly.
 */
struct pktqueue *pktqueue_create(void);
/**
 * Call during destruction to avoid memory leaks.
 */
void pktqueue_destroy(struct pktqueue *queue);

void pktqueue_config_copy(struct pktqueue *queue, struct pktqueue_config *config);
void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config);

/**
 * Stores packet "skb", associating it with "session".
 */
int pktqueue_add(struct pktqueue *queue, struct pktqueue_session *session,
		struct packet *pkt);
/**
 * Removes "session"'s skb from the storage. There will be no ICMP error.
 */
void pktqueue_rm(struct pktqueue *queue, struct pktqueue_session *session);

void pktqueue_clean(struct pktqueue *queue);


#endif /* _JOOL_MOD_PKT_QUEUE_H */
