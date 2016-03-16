#!/bin/bash

graybox expect add $2-nodf-frag0.pkt $3
graybox expect add $2-nodf-frag1.pkt $3
graybox expect add $2-nodf-frag2.pkt $3

graybox send $1-nodf-frag0.pkt
graybox send $1-nodf-frag1.pkt
graybox send $1-nodf-frag2.pkt

sleep 0.1

graybox expect flush
