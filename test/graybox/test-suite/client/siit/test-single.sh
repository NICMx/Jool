#!/bin/bash

GRAYBOX=graybox

if [ -n "${3+x}" ]; then $GRAYBOX -ga --numArray $3; fi

$GRAYBOX -ra --pkt $2-nofrag.pkt
$GRAYBOX -sa --pkt $1-nofrag.pkt

sleep 0.1

if [ -n "${3+x}" ]; then $GRAYBOX -gf; fi
$GRAYBOX -rf
