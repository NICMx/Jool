#!/bin/bash

graybox expect add $2-nofrag.pkt $3
graybox send $1-nofrag.pkt

sleep 0.1

graybox expect flush

