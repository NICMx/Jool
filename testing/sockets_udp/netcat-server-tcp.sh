#!/bin/bash

PORT="4369"

echo "Chatting using 'netcat' through 'TCP' port $PORT "
netcat    -l $PORT

