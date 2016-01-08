#!/bin/bash

GRAYBOX=graybox

if [ -n "${3+x}" ]; then $GRAYBOX -ga --numArray $3; fi

$GRAYBOX -ra --pkt $2-nodf-frag0.pkt
$GRAYBOX -ra --pkt $2-nodf-frag1.pkt
$GRAYBOX -ra --pkt $2-nodf-frag2.pkt

$GRAYBOX -sa --pkt $1-nodf-frag0.pkt
$GRAYBOX -sa --pkt $1-nodf-frag1.pkt
$GRAYBOX -sa --pkt $1-nodf-frag2.pkt

sleep 0.1

if [ -n "${3+x}" ]; then $GRAYBOX -gf; fi
$GRAYBOX -rf

