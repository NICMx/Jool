#!/bin/bash

MODULE=`sed -n -e '/[#]/ d' -e '/obj-m/ { s/obj-m \++= \+// ; s/.o/.ko/ ; p ;} ' Makefile `

sudo dmesg -c
reset

echo ">>> Clean module" && \
make clean && \
echo "" && \
echo ">>> Make module" && \
make 

[ -f ./$MODULE ] && \
echo "" && \
echo ">>> Remove module" && \
sudo  rmmod ./$MODULE > /dev/null 2>&1

[ -f ./$MODULE ] && \
echo "" && \
echo ">>> Insert module" && \
sudo insmod ./$MODULE

[ -f ./$MODULE ] && \
echo "" && \
echo ">>> Remove module" && \
sudo  rmmod ./$MODULE > /dev/null 2>&1

[ -f ./$MODULE ] && \
echo "" && \
dmesg | tail -20


