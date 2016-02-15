#!/bin/bash
# This script will simply execute all the necesary commands to compile and mount the graybox kernel module, compile the script executor, setup the environment and execute the tests
JOOL_GRAYBOX=$(pwd)

cd $JOOL_GRAYBOX/mod
make
sudo make modules_install

cd $JOOL_GRAYBOX/usr
make
sudo make install

cd $JOOL_GRAYBOX/test-suite/xlat/
chmod +x *.sh
./siit-netns.sh
sleep 10
cd $JOOL_GRAYBOX/test-suite/client/siit/
chmod +x *.sh
./send.sh
./end.sh
cd $JOOL_GRAYBOX/test-suite/xlat/
./end-netns.sh
./nat64-netns.sh
sleep 10
cd $JOOL_GRAYBOX/test-suite/client/nat64
chmod +x *.sh
./send.sh
./end.sh
cd $JOOL_GRAYBOX/test-suite/xlat/
./end-netns.sh

cd $JOOL_GRAYBOX/mod
make clean

cd $JOOL_GRAYBOX/usr
sudo make uninstall
make clean
