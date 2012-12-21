#ifndef _NAT64_STATIC_ROUTES_H
#define _NAT64_STATIC_ROUTES_H

#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/in.h>
#include "xt_nat64_module_comm.h"
#include "nf_nat64_session.h"
#include "nf_nat64_types.h"
#include "nf_nat64_config.h"

/** 
 * @file nf_nat64_static_routes.h
 *
 * This header contains the function prototypes for the
 * nf_nat64_static_routes.c module
 *
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
bool nat64_add_static_route(struct route_struct *rst);

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
bool nat64_delete_static_route(struct route_struct *rst);


/**
 * nat64_print_bib_table - prints route table
 * @param  rst  The struct where the route is contained.
 *
 * It obtains bib information from the table and sends it back
 * to userpsace
 */
bool nat64_print_bib_table(struct route_struct *rst, __u32 *count_out,
		struct bib_entry_us **bibs_us_out);


/**
 * nat64_print_session_table - prints route table
 * @param  rst  The struct where the route is contained.
 *
 * It obtains session information from the table and sends it back
 * to userpsace
 */
bool nat64_print_session_table(struct route_struct *rst, __u32 *count_out,
		struct session_entry_us **sessions_us_out);

#endif
