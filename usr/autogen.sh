#!/bin/bash

aclocal
automake --add-missing --copy
autoconf
rm -r autom4te.cache

