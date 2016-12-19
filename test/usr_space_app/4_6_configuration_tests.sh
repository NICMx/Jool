#!/bin/bash

# Initialize testing framework
source library.sh


### NAT64 not running
COMMAND=jool
OPTS="--bib"
VALUES=( '' )
RETURNS=( ERR1000 )
KERNMSG=( NOERR )
test_options

### SIIT not running
COMMAND=jool_siit
OPTS="--eamt"
VALUES=( '' )
RETURNS=( ERR1000 )
KERNMSG=( NOERR )
test_options


print_summary
