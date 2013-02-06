#ifndef _NAT64_STATIC_ROUTES_H
#define _NAT64_STATIC_ROUTES_H

#include "nat64/config_proto.h"


/** 
 * @file
 * A bridge between the configuration module and the BIB and session modules.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

/**
 * nat64_add_static_route - adds a static route
 * @param  rst  The struct where the route is contained.
 * @param  buffer  The char buffer where the IPv4 addres from the pool 
 * is contained.
 *
 * It obtains the data from the struct and detects each parameter needed
 * to add a static route to the BIB and Session Table of NAT64.
 *
 */
enum response_code nat64_add_static_route(struct request_session *req);

/**
 * nat64_delete_static_route - deletes a static route
 * @param  rst  The struct where the route is contained.
 * @param  buffer  The char buffer where the IPv4 addres from the pool 
 * is contained.
 *
 * It obtains the data from the struct and detects each parameter needed
 * to delete a static route to the BIB and Session Table of NAT64.
 *
 */
enum response_code nat64_delete_static_route(struct request_session *req);


/**
 * nat64_print_bib_table - prints route table
 * @param  rst  The struct where the route is contained.
 *
 * It obtains bib information from the table and sends it back
 * to userpsace
 */
enum response_code nat64_print_bib_table(union request_bib *request, __u16 *count_out,
		struct bib_entry_us **bibs_us_out);


/**
 * nat64_print_session_table - prints route table
 * @param  rst  The struct where the route is contained.
 *
 * It obtains session information from the table and sends it back
 * to userpsace
 */
enum response_code nat64_print_session_table(struct request_session *request, __u16 *count_out,
		struct session_entry_us **sessions_us_out);

#endif
