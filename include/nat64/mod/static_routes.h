#ifndef _NAT64_STATIC_ROUTES_H
#define _NAT64_STATIC_ROUTES_H

#include "nat64/comm/config_proto.h"


/** 
 * @file
 * A bridge between the configuration module and the BIB and session modules.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

/**
 * add_static_route - adds a static route
 * @param  rst  The struct where the route is contained.
 * @param  buffer  The char buffer where the IPv4 addres from the pool 
 * is contained.
 *
 * It obtains the data from the struct and detects each parameter needed
 * to add a static route to the BIB and Session Table of NAT64.
 *
 */
int add_static_route(struct request_session *req);

/**
 * delete_static_route - deletes a static route
 * @param  rst  The struct where the route is contained.
 * @param  buffer  The char buffer where the IPv4 addres from the pool 
 * is contained.
 *
 * It obtains the data from the struct and detects each parameter needed
 * to delete a static route to the BIB and Session Table of NAT64.
 *
 */
int delete_static_route(struct request_session *req);


#endif
