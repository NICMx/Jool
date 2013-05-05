#!/bin/bash

export EXP_DIR="../"
export WORK_DIR="$EXP_DIR/usr"
export MOD_DIR="$EXP_DIR/mod"
export LOGS_DIR="./logs"

export APP="nat64"
export COMMAND="$WORK_DIR/$APP"
#export MAKE_MOD="make -f $MOD_DIR/Makefile insert"

export IPV6_ROUTER="c0ca:db8:2001:1::1"
#~ export IPV4_ROUTER="64:ff9b::10.17.46.1"
export IPV4_ROUTER="64:ff9b::192.168.1.2"
