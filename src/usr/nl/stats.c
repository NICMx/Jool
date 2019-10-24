#include "stats.h"

#include <errno.h>

#include "common/config.h"
#include "jool_socket.h"

#define DEFINE_STAT(_id, _doc) { \
		.id = _id, \
		.name = #_id, \
		.doc = _doc, \
	}

#define TC "Translations cancelled: "

static struct jstat_metadata const jstat_metadatas[] = {
	DEFINE_STAT(JSTAT_SUCCESS, "Successful translations. (Note: 'Successful translation' does not imply that the packet was actually delivered.)"),
	DEFINE_STAT(JSTAT_BIB_ENTRIES, "Number of BIB entries currently held in the BIB."),
	DEFINE_STAT(JSTAT_SESSIONS, "Number of session entries currently held in the BIB."),
	DEFINE_STAT(JSTAT_ENOMEM, "Memory allocation failures."),
	DEFINE_STAT(JSTAT_XLATOR_DISABLED, TC "Translator was manually disabled."),
	DEFINE_STAT(JSTAT_POOL6_UNSET, TC "pool6 was unset."),
	DEFINE_STAT(JSTAT_SKB_SHARED, TC "Packet was shared. (In the kernel, when packets are 'shared', they cannot be modified.)"),
	DEFINE_STAT(JSTAT_L3HDR_OFFSET, TC "Packet corrupted; Network header offset is not relative to skb->data."),
	DEFINE_STAT(JSTAT_SKB_TRUNCATED, TC "Packet corrupted; Data stopped in the middle of a header."),
	DEFINE_STAT(JSTAT_FRAGMENTED_PING, TC "Packet was a fragmented ping, so its checksum was impossible to translate."),
	DEFINE_STAT(JSTAT_HDR6, TC "Some IPv6 header field was bogus. (Eg. version was not 6.)"),
	DEFINE_STAT(JSTAT_HDR4, TC "Some IPv4 header field was bogus. (Eg. version was not 4.)"),
	DEFINE_STAT(JSTAT_UNKNOWN_L4_PROTO, TC "Packet carried an unknown transport protocol. (Untranslatable by NAT64.)"),
	DEFINE_STAT(JSTAT_UNKNOWN_ICMP6_TYPE, TC "ICMPv6 header's type value has no ICMPv4 counterpart."),
	DEFINE_STAT(JSTAT_UNKNOWN_ICMP4_TYPE, TC "ICMPv4 header's type value has no ICMPv6 counterpart."),
	DEFINE_STAT(JSTAT_DOUBLE_ICMP6_ERROR, TC "ICMPv6 error contained another ICMPv6 error. (Which is illegal.)"),
	DEFINE_STAT(JSTAT_DOUBLE_ICMP4_ERROR, TC "ICMPv4 error contained another ICMPv4 error. (Which is illegal.)"),
	DEFINE_STAT(JSTAT_UNKNOWN_PROTO_INNER, TC "ICMP error's inner packet had an unknown transport protocol. (Untranslatable by NAT64.)"),
	DEFINE_STAT(JSTAT_HAIRPIN_LOOP, TC "Incoming IPv6 packet's source address matches pool6. (Only the destination address should match pool6.)\n"
			"You have to think of the IPv4 network as an IPv6 network whose prefix is pool6. If your actual IPv6 client also has the pool6 prefix, then your setup risks IP address collision.\n"
			"Either change the client's address or fix your pool6 so it represents a unique network."),
	DEFINE_STAT(JSTAT_POOL6_MISMATCH, TC "IPv6 packet's destination address did not match pool6. (ie. Packet was not meant to be translated.)"),
	DEFINE_STAT(JSTAT_POOL4_MISMATCH, TC "IPv4 packet's destination address and transport protocol did not match pool4. (ie. Packet was not meant to be translated.)\n"
			"If the instance is a Netfilter translator, this counter increases randomly from normal operation, and is harmless.\n"
			"If the instance is an iptables translator, this counter being positive suggests a mismatch between the IPv4 iptables rule(s) and the instance's configuration."),
	DEFINE_STAT(JSTAT_ICMP6_FILTER, "Packets filtered by `" OPTNAME_DROP_ICMP6_INFO "` policy."),
	/* TODO This one might signal a programming error. */
	DEFINE_STAT(JSTAT_UNTRANSLATABLE_DST6, TC "IPv6 packet's destination address did not match pool6."),
	DEFINE_STAT(JSTAT_UNTRANSLATABLE_DST4, TC "IPv4 packet's source address could not be translated with the given pool6."),
	DEFINE_STAT(JSTAT_MASK_DOMAIN_NOT_FOUND, TC "There was no pool4 entry whose protocol and mark matched the incoming IPv6 packet."),
	DEFINE_STAT(JSTAT_BIB6_NOT_FOUND, TC "IPv6 packet did not match a BIB entry from the database, and one could not be created."),
	DEFINE_STAT(JSTAT_BIB4_NOT_FOUND, TC "IPv4 packet did not match a BIB entry from the database."),
	DEFINE_STAT(JSTAT_SESSION_NOT_FOUND, TC "Packet was an ICMP error, but did not match a session entry from the database. (Which means that the original packet couldn't have been translated.)"),
	DEFINE_STAT(JSTAT_ADF, "Packets filtered by `" OPTNAME_DROP_BY_ADDR "` policy."),
	DEFINE_STAT(JSTAT_V4_SYN, "Packets filtered by `" OPTNAME_DROP_EXTERNAL_TCP "` policy."),
	DEFINE_STAT(JSTAT_SYN6_EXPECTED, TC "Incoming IPv6 packet was the first of a TCP connection, but its SYN flag was disabled."),
	DEFINE_STAT(JSTAT_SYN4_EXPECTED, TC "Incoming IPv4 packet was the first of a TCP connection, but its SYN flag was disabled."),
	DEFINE_STAT(JSTAT_TYPE1PKT, "Total number of Type 1 packets stored. (See https://github.com/NICMx/Jool/blob/584a846d09e891a0cd6342426b7a25c6478c90d6/src/mod/nat64/bib/pkt_queue.h#L77) (This counter is not decremented when a packet leaves the queue.)"),
	DEFINE_STAT(JSTAT_TYPE2PKT, "Total number of Type 2 packets stored. (See https://github.com/NICMx/Jool/blob/584a846d09e891a0cd6342426b7a25c6478c90d6/src/mod/nat64/bib/pkt_queue.h#L77) (This counter is not decremented when a packet leaves the queue.)"),
	DEFINE_STAT(JSTAT_SO_EXISTS, TC "Packet was a Simultaneous Open retry. (Client was trying to punch a hole, and was being unnecessarily greedy.)"),
	DEFINE_STAT(JSTAT_SO_FULL, TC "Packet queue was full, so the Simultaneous Open attempt was denied. (Too many clients were trying to punch holes.)"),
	DEFINE_STAT(JSTAT64_SRC, TC "IPv6 packet's source address did not match pool6 nor any EAMT entries, or the resulting address was blacklist4ed."),
	DEFINE_STAT(JSTAT64_DST, TC "IPv6 packet's destination address did not match pool6 nor any EAMT entries, or the resulting address was blacklist4ed."),
	DEFINE_STAT(JSTAT64_PSKB_COPY, TC "It was not possible to allocate the IPv4 counterpart of the IPv6 packet. (The kernel's pskb_copy() function failed.)"),
	DEFINE_STAT(JSTAT64_ICMP_CSUM, TC "Incoming ICMPv6 error packet's checksum was incorrect."),
	DEFINE_STAT(JSTAT64_UNTRANSLATABLE_DEST_UNREACH, TC "Packet was an ICMPv6 Destination Unreachable error message, and its code has no ICMPv4 counterpart."),
	DEFINE_STAT(JSTAT64_UNTRANSLATABLE_PARAM_PROB, TC "Packet was an ICMPv6 Parameter Problem error message, and its code has no ICMPv4 counterpart."),
	DEFINE_STAT(JSTAT64_UNTRANSLATABLE_PARAM_PROB_PTR, TC "Packet was an ICMv6 Parameter Problem error message, but its pointer was untranslatable."),
	DEFINE_STAT(JSTAT64_TTL, TC "IPv6 packet's Hop Limit field was 0 or 1."),
	DEFINE_STAT(JSTAT64_SEGMENTS_LEFT, TC "IPv6 packet had a Segments Left field, and it was nonzero."),
	DEFINE_STAT(JSTAT46_SRC, TC "IPv4 packet's source address was blacklist4ed, or did not match pool6 nor any EAMT entries."),
	DEFINE_STAT(JSTAT46_DST, TC "IPv4 packet's destination address was blacklist4ed, or did not match pool6 nor any EAMT entries."),
	DEFINE_STAT(JSTAT46_PSKB_COPY, TC "It was not possible to allocate the IPv6 counterpart of the IPv4 packet. (The kernel's __pskb_copy() function failed.)"),
	DEFINE_STAT(JSTAT46_ICMP_CSUM, TC "Incoming ICMPv4 error packet's checksum was incorrect."),
	DEFINE_STAT(JSTAT46_UNTRANSLATABLE_DEST_UNREACH, TC "Packet was an ICMPv4 Destination Unreachable error message, and its code has no ICMPv6 counterpart."),
	DEFINE_STAT(JSTAT46_UNTRANSLATABLE_PARAM_PROB, TC "Packet was an ICMPv4 Parameter Problem error message, and its code has no ICMPv6 counterpart."),
	DEFINE_STAT(JSTAT46_UNTRANSLATABLE_PARAM_PROBLEM_PTR, TC "Packet was an ICMv4 Parameter Problem error message, but its pointer was untranslatable."),
	DEFINE_STAT(JSTAT46_TTL, TC "IPv4 packet's TTL field was 0 or 1."),
	DEFINE_STAT(JSTAT46_SRC_ROUTE, TC "Packet had an unexpired Source Route. (Untranslatable.)"),
	DEFINE_STAT(JSTAT46_FRAGMENTED_ZERO_CSUM, TC "IPv4 packet was UDP, fragmented and had zero for a checksum. This checksum cannot be computed by a stateless translator."),
	DEFINE_STAT(JSTAT_FAILED_ROUTES, TC "The translated packet could not be routed; the kernel's routing function errored. Cause is unknown. (It usually happens because the packet's destination address could not be found in the routing table.)"),
	DEFINE_STAT(JSTAT_PKT_TOO_BIG, TC "Translated IPv4 packet did not fit in the outgoing interface's MTU. A Packet Too Big or Fragmentation Needed ICMP error was returned to the client."),
	DEFINE_STAT(JSTAT_DST_OUTPUT, TC "Translation was successful but the kernel's packet dispatch function (dst_output()) returned nonzero."),
	DEFINE_STAT(JSTAT_ICMP6ERR_SUCCESS, "ICMPv6 errors (created by Jool, not translated) sent successfully."),
	DEFINE_STAT(JSTAT_ICMP6ERR_FAILURE, "ICMPv6 errors (created by Jool, not translated) that could not be sent."),
	DEFINE_STAT(JSTAT_ICMP4ERR_SUCCESS, "ICMPv4 errors (created by Jool, not translated) sent successfully."),
	DEFINE_STAT(JSTAT_ICMP4ERR_FAILURE, "ICMPv4 errors (created by Jool, not translated) that could not be sent."),
	DEFINE_STAT(JSTAT_UNKNOWN, TC "Unknown error. Likely a programming error."),
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

static struct jool_result validate_stats(void)
{
	unsigned int i;

	if (ARRAY_SIZE(jstat_metadatas) != __JSTAT_MAX)
		goto failure;

	for (i = 0; i < __JSTAT_MAX; i++) {
		if (i != jstat_metadatas[i].id)
			goto failure;
	}

	return result_success();

failure:
	return result_from_error(
		-EINVAL,
		"Programming error: The jstat_metadatas array does not match the jool_stat_id enum."
	);
}

struct query_args {
	stats_foreach_cb cb;
	void *args;
};

static struct jool_result stats_query_response(struct jool_response *response,
		void *args)
{
	size_t expected_len;
	__u64 *values = response->payload;
	struct jstat stat;
	struct query_args *qargs = args;
	unsigned int i;
	struct jool_result result;

	expected_len = __JSTAT_MAX * sizeof(*values);
	if (expected_len != response->payload_len) {
		return result_from_error(
			-EINVAL,
			"Jool's response has a bogus length. (expected %zu, got %zu).",
			expected_len, response->payload_len
		);
	}

	for (i = 0; i < __JSTAT_MAX; i++) {
		stat.meta = jstat_metadatas[i];
		stat.value = values[i];
		result = qargs->cb(&stat, qargs->args);
		if (result.error)
			return result;
	}

	return result_success();
}

struct jool_result stats_foreach(struct jool_socket *sk, char *iname,
		stats_foreach_cb cb, void *args)
{
	struct query_args qargs;
	struct request_hdr request;
	struct jool_result result;

	result = validate_stats();
	if (result.error)
		return result;

	qargs.cb = cb;
	qargs.args = args;
	init_request_hdr(&request, sk->xt, MODE_STATS, OP_FOREACH, false);

	return netlink_request(sk, iname, &request, sizeof(request),
			stats_query_response, &qargs);
}
