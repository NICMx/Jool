#!/usr/bin/env bash

. config

cd $JOOL_DIR/test/unit
make
./test.sh
make clean

