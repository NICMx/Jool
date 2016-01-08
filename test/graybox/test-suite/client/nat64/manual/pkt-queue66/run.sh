#!/bin/bash

sudo modprobe graybox

#sudo ~/bin/graybox -ga --numArray 1,5,6,10,11
sudo ~/bin/graybox -ra --pkt pkt-queue66-receiver-nofrag.pkt
sudo ~/bin/graybox -sa --pkt pkt-queue66-sender-nofrag.pkt

sleep 6.1s
sudo modprobe -r graybox
sudo dmesg -c

