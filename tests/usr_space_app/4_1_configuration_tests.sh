#!/bin/bash

# Load environment configuration
source environment.sh

POSTFIX=`date +%F_%T`
OUTPUT="$LOGS_DIR/`basename $0`_$POSTFIX.log" # Un-comment this
#OUTPUT="/dev/null" # Debug

# Clear the system messages 
sudo dmesg -c > /dev/null  # Un-comment this
#echo	sudo dmesg -c > /dev/null # Debug

TEST_FAIL=0
TEST_PASS=0
TEST_COUNT=0

# Load testing code
source library.sh

# Insert module
nat64_mod_remove
nat64_mod_insert


### Filtering UDP
SECTION="--filtering"
OPTS="--toUDP"
VALUES=( -1 abc 120 )
RETURNS=( ERR1008 ERR1007 success )
test_options

### Filtering TCP
SECTION="--filtering"
OPTS="--toTCPest"
VALUES=( 500 abc 7200 )
RETURNS=( ERR1008 ERR1007 success )
test_options

SECTION="--filtering"
OPTS="--toTCPtrans"
VALUES=( 100 gfh 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options

### Filtering ICMP
SECTION="--filtering"
OPTS="--toICMP"
VALUES=( 66000 abc 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options

### Filtering TOS
SECTION="--filtering"
OPTS="--TOS"
VALUES=( -1 abc 100 )
RETURNS=( ERR1008 ERR1007 success )
test_options

#~ ### Filtering MTU
#~ SECTION="--filtering"
#~ OPTS="--nextMTU6"
#~ VALUES=( 70000 abc 1000 )
#~ RETURNS=( ERR1008 ERR1007 success )
#~ test_options
#~ 
#~ SECTION="--filtering"
#~ OPTS="--nextMTU4"
#~ VALUES=( -1 aaa 1000 )
#~ RETURNS=( ERR1008 ERR1007 success )
#~ test_options

### Filtering head & tail
SECTION="--filtering"
OPTS="--head"
VALUES=( -1 aaa 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options

SECTION="--filtering"
OPTS="--tail"
VALUES=( -1 abc 1000 )
RETURNS=( ERR1008 ERR1007 success )
test_options


## Filtering filter
SECTION="--filtering"
OPTS="--dropAddr"
VALUES=( abc 10 0 )
RETURNS=( ERR1006 ERR1006 success )
test_options

SECTION="--filtering"
OPTS="--dropInfo"
VALUES=( ' ' 10 "false" )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Un-implemented option
#SECTION="--filtering"
#OPTS="--dropTcp"
#VALUES=( 22 10 on )
#RETURNS=( ERR1006 ERR1006 success )
#test_options

### Translate TC 
SECTION="--translate"
OPTS="--setTC"
VALUES=( null 10 off )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate TOS 
SECTION="--translate"
OPTS="--setTOS"
VALUES=( null 10 "true" )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate genID 
SECTION="--translate"
OPTS="--genID"
VALUES=( abc 10 "true" )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate setDF
SECTION="--translate"
OPTS="--setDF"
VALUES=( "--" 10 1 )
RETURNS=( ERR1006 ERR1006 success )
test_options

### Translate boostMTU
SECTION="--translate"
OPTS="--boostMTU"
VALUES=( "." 10 0 )
RETURNS=( ERR1006 ERR1006 success )
test_options

print_resume
