#ifndef _NAT64_STATIC_ROUTES_H
#define _NAT64_STATIC_ROUTES_H

#include <linux/string.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <asm/uaccess.h>


void nat64_create_character_device(void);
void nat64_destroy_character_device(void);
static inline void nat64_add_static_route(char *b);

#endif