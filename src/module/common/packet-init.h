#ifndef SRC_MODULE_COMMON_PACKET_INIT_H_
#define SRC_MODULE_COMMON_PACKET_INIT_H_

/*
 * In case you're wondering, the reason why I don't want to include this in the
 * packet.h module is because packet initialization is a high-level step (Along
 * with "Determine Incoming Tuple", "Filtering and Updating" and friends), not
 * a low-level/basic operation. Also, in practice, xlation.h should not be
 * included in a core file such as packet.h.
 */

#include "xlation.h"

/**
 * Ensures @skb isn't corrupted and initializes @state->pkt.in out of it.
 *
 * After this function, code can assume:
 * - @skb contains full l3 and l4 headers (including inner ones), their order
 *   seems to make sense, and they are all within the head room of @skb.
 * - @skb's payload isn't truncated (though inner packet payload might).
 * - The pkt_* functions above can now be used on @state->pkt.in.
 * - The length fields in the l3 headers can be relied upon.
 *
 * Healthy layer 4 checksums and lengths are not guaranteed, but that's not an
 * issue since this kind of corruption should be translated along (see
 * validate_icmp6_csum()).
 *
 * Also, this function does not ensure @skb is either TCP, UDP or ICMP. This is
 * because SIIT Jool must translate other protocols in a best-effort basis.
 *
 * This function can change the packet's pointers. If you eg. stored a pointer
 * to skb_network_header(skb), you will need to assign it again (by calling
 * skb_network_header() again).
 */
int pkt_init_ipv6(struct xlation *state, struct sk_buff *skb);
int pkt_init_ipv4(struct xlation *state, struct sk_buff *skb);

#endif /* SRC_MODULE_COMMON_PACKET_INIT_H_ */
