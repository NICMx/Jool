#!/bin/bash

PORT="4369"

echo "Chatting using 'netcat' through 'UDP' port $PORT "
netcat -u -l $PORT

