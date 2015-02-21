#ifndef _JOOL_MOD_PKT_QUEUE_H
#define _JOOL_MOD_PKT_QUEUE_H

/**
 * @file
 * As the name implies, this is just a small database of packets. These packets are meant to be
 * replied (in the form of a ICMP error) in the future.
 *
 * You can find the specifications for this in pages 28 and 29 (look up "simultaneous open of TCP
 * connections"), and 30 (look up "stored is sent back") from RFC 6146.
 *
 * The RFC gets a little nonsensical here. These requirements seem to exist to satisfy REQ-4 of RFC
 * 5382 (http://ietf.10.n7.nabble.com/Simultaneous-connect-td222455.html), except RFC 5382 wants us
 * to cancel the ICMP error "If during this interval the NAT receives and translates an outbound
 * SYN for the connection", but this is not very explicit in the specification of the V4_INIT state
 * in RFC 6146. I mean it's the only state where the session expiration triggers the ICMP message,
 * but it'd be nice to see confirmation that the stored packet can be forgotten about.
 *
 * However, Marcelo Bagnulo's seemingly final comments really bend me over to RFC 5382's behavior:
 * "well, it may be sent inside an ICMP error message in case the state times out and the V& SYN
 * has not arrived."
 * http://ietf.10.n7.nabble.com/Re-Last-Call-draft-ietf-behave-v6v4-xlate-stateful-Stateful-NAT64-Network-Address-and-Protocol-Transd-td70142.html
 *
 * So... yeah, "Packet Storage". This is how I understand it:
 *
 * If a NAT64 receives a IPv4-UDP or a IPv4-ICMP packet for which it has no state, it should reply
 * a ICMP error because it doesn't know which IPv6 node the packet should be forwarded to.
 *
 * If a NAT64 receives a IPv4-TCP packet for which it has no state, it should not immediately reply
 * a ICMP error because the IPv4 endpoint could be attempting a "Simultaneous Open of TCP
 * Connections" (https://github.com/NICMx/NAT64/issues/58#issuecomment-43537094). What happens is
 * the NAT64 stores the packet for 6 seconds; if the IPv6 version of the packet arrives, the NAT64
 * drops the original packet (the IPv4 node will eventually realize this on its own by means of the
 * handshake), otherwise a ICMP error containing the original IPv4 packet is generated (because
 * there's no Simultaneous Open going on).
 *
 * @author Angel Cazares
 * @author Daniel Hernandez
 * @author Alberto Leiva
 */

#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/session_db.h"

/**
 * Call during initialization for the remaining functions to work properly.
 */
int pktqueue_init(void);
/**
 * Call during destruction to avoid memory leaks.
 */
void pktqueue_destroy(void);

/**
 * Stores packet "skb", associating it with "session".
 */
int pktqueue_add(struct session_entry *session, struct packet *pkt);
/**
 * Sends "session"'s reply and removes it from the DB.
 */
int pktqueue_send(struct session_entry *session);
/**
 * Removes "session"'s skb from the storage. There will be no ICMP error.
 */
int pktqueue_remove(struct session_entry *session);


#endif /* _JOOL_MOD_PKT_QUEUE_H */
