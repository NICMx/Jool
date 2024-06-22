# Graybox

The "graybox" tests are the logical step after the unit tests. They are a bunch of packet exchanges between a custom IPv6/v4 raw packet sender and validator (named `graybox`) and an actual Jool binary.

The name used to stem from "Gray Box Testing," but it quickly became an additional white box.

## Compiling the test binaries

Install libnl-genl-3-dev, then

	./autogen.sh
	./configure
	make

Don't install these binaries; it's not necessary nor recommended.

## Running the test suite

See [`test-suite/README.md`](test-suite/README.md)
