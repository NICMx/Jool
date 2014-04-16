#include "nat64/usr/session.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/str_utils.h"
#include "nat64/usr/netlink.h"
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

extern struct session_config session_config;

static void getname_ipv6_tupple(struct ipv6_tuple_address t, char* host, size_t hostlen, char* serv, size_t servlen)
{
	struct sockaddr_in6 sa6;
	int err;
	memset(&sa6, 0, sizeof(struct sockaddr_in6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(t.l4_id);
	sa6.sin6_addr = t.address;
	err = getnameinfo((const struct sockaddr*)&sa6, sizeof(sa6), host, hostlen, serv, servlen, 0);
	if (err != 0) {
		log_info("getnameinfo failed: %s\n", gai_strerror(err));
	}
}

static void getname_ipv4_tupple(struct ipv4_tuple_address t, char* host, size_t hostlen, char* serv, size_t servlen)
{
	struct sockaddr_in sa;
	int err;
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(t.l4_id);
	sa.sin_addr = t.address;
	err = getnameinfo((const struct sockaddr*)&sa, sizeof(sa), host, hostlen, serv, servlen, 0);
	if (err != 0) {
		log_info("getnameinfo failed: %s\n", gai_strerror(err));
	}
}

static int session_display_response(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	struct session_entry_us *entries;
	__u16 entry_count, i;

	hdr = nlmsg_hdr(msg);
	entries = nlmsg_data(hdr);
	entry_count = nlmsg_datalen(hdr) / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		struct session_entry_us *entry = &entries[i];

		printf("Expires in ");
		print_time(entry->dying_time);
		if (session_config.numeric_hostname) {
			char *str4;
			char str6[INET6_ADDRSTRLEN];

			str4 = inet_ntoa(entry->ipv4.remote.address);
			printf("Remote: %s#%u\t", str4, entry->ipv4.remote.l4_id);
			inet_ntop(AF_INET6, &entry->ipv6.remote.address, str6, INET6_ADDRSTRLEN);
			printf("%s#%u\n", str6, entry->ipv6.remote.l4_id);

			str4 = inet_ntoa(entry->ipv4.local.address);
			printf("Local: %s#%u\t", str4, entry->ipv4.local.l4_id);
			inet_ntop(AF_INET6, &entry->ipv6.local.address, str6, INET6_ADDRSTRLEN);
			printf("%s#%u\n", str6, entry->ipv6.local.l4_id);
		}
		else {
			char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

			getname_ipv4_tupple(entry->ipv4.remote, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf));
			printf("Remote: %s#%s\t", hbuf, sbuf);

			getname_ipv6_tupple(entry->ipv6.remote, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf));
			printf("%s#%s\n", hbuf, sbuf);

			getname_ipv4_tupple(entry->ipv4.local, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf));
			printf("Local: %s#%s\t", hbuf, sbuf);

			getname_ipv6_tupple(entry->ipv6.local, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf));
			printf("%s#%s\n", hbuf, sbuf);
		}
		printf("---------------------------------\n");
	}

	*((int *) arg) += entry_count;
	return 0;
}

static bool display_single_table(char *table_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);
	int row_count = 0;
	bool error;

	printf("%s:\n", table_name);
	printf("---------------------------------\n");

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_DISPLAY;
	payload->l4_proto = l4_proto;

	error = netlink_request(request, hdr->length, session_display_response, &row_count);
	if (!error) {
		if (row_count > 0)
			log_info("  (Fetched %u entries.)\n", row_count);
		else
			log_info("  (empty)\n");
	}

	return error;
}

int session_display(bool use_tcp, bool use_udp, bool use_icmp)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_table("TCP", L4PROTO_TCP);
	if (use_udp)
		udp_error = display_single_table("UDP", L4PROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_table("ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}

static int session_count_response(struct nl_msg *msg, void *arg)
{
	__u64 *conf = nlmsg_data(nlmsg_hdr(msg));
	printf("%llu\n", *conf);
	return 0;
}

static bool display_single_count(char *count_name, u_int8_t l4_proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	struct request_session *payload = (struct request_session *) (request + HDR_LEN);

	printf("%s: ", count_name);

	hdr->length = sizeof(request);
	hdr->mode = MODE_SESSION;
	hdr->operation = OP_COUNT;
	payload->l4_proto = l4_proto;

	return netlink_request(request, hdr->length, session_count_response, NULL);
}

int session_count(bool use_tcp, bool use_udp, bool use_icmp)
{
	int tcp_error = 0;
	int udp_error = 0;
	int icmp_error = 0;

	if (use_tcp)
		tcp_error = display_single_count("TCP", L4PROTO_TCP);
	if (use_udp)
		udp_error = display_single_count("UDP", L4PROTO_UDP);
	if (use_icmp)
		icmp_error = display_single_count("ICMP", L4PROTO_ICMP);

	return (tcp_error || udp_error || icmp_error) ? -EINVAL : 0;
}
