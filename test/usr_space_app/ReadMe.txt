In order to test the user-space app's configuration, first make sure the app
is compiled:

../../usr$ make

Also insert the NAT64:

../../mod$ make
../../mod$ make insert

And then run each one of the scripts inside this directory. That is, from
4_1_*.sh to 4_6_*.sh.

$ reset; for nn in `seq 1 6`; do ./4_$nn*.sh ; done
