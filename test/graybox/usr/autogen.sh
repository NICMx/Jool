#!/bin/bash

# Hello.
# Run this file to generate the configure script.
# You'll need Autoconf and Automake installed!

aclocal
automake --add-missing --copy
autoconf

