#!/bin/bash
# This script will simply execute all the necesary commands to compile and mount the graybox kernel module, compile the script executor, setup the environment and execute the tests
JOOL_GRAYBOX=$(pwd)
cd $JOOL_GRAYBOX/mod
sudo make
sudo make modules_install

cd $JOOL_GRAYBOX/usr
sudo make
sudo make install

cd $JOOL_GRAYBOX/test-suite/xlat/
./siit-netns.sh
cd $JOOL_GRAYBOX/test-suite/client/siit/
./send.sh
./end.sh
cd $JOOL_GRAYBOX/test-suite/xlat/
./end-netns.sh
./nat64-netns.sh
cd $JOOL_GRAYBOX/test-suite/client/
./send.sh
./end.sh
cd $JOOL_GRAYBOX/test-suite/xlat/
./end-netns.sh