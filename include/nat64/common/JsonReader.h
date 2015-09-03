/*
 * JsonReader.h
 *
 *  Created on: Jul 31, 2015
 *      Author: rolivas
 */

#ifndef JSONREADER_H_
#define JSONREADER_H_

#include <stddef.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "nat64/usr/cJSON.h"
#include "nat64/usr/str_utils.h"
#include "nat64/usr/netlink.h"
#include "nat64/common/config.h"
#include "nat64/usr/types.h"



int parse_file(char * fileName);



#endif /* JSONREADER_H_ */

