#!/bin/bash

ipv4_server="64:ff9b::192.168.1.4"
PORT="4369"

echo "Chating with $ipv4_server using 'netcat' through 'TCP' port $PORT"
nc.openbsd -6    $ipv4_server $PORT

