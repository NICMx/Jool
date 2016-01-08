#!/bin/bash

sudo modprobe graybox

# Why is the TOS different?
sudo ~/bin/graybox -ga --numArray 1,4,5,6,10,11
sudo ~/bin/graybox -ra --pkt pkt-queue46-receiver-nofrag.pkt
sudo ~/bin/graybox -sa --pkt pkt-queue46-sender-nofrag.pkt

sleep 6.1s
sudo modprobe -r graybox
sudo dmesg -c

