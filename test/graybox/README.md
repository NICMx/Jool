# Graybox Tests

The "graybox" tests are the logical step after the unit tests. They are a bunch of packet exchanges between a custom IPv6/v4 raw packet sender and validator (named `graybox`) and an actual Jool binary.

Requires a successful installation of both kernel and userspace binaries of SIIT and/or NAT64 Jool.

## Compiling the test suite

None of this requires privileges.

```bash
cd mod
make
cd ../usr
./autogen.sh # only needed if the `configure` file does not exist.
./configure && make
```

Do not install them; it's not necessary.

## Running the test suite

You might need to stop the network manager beforehand.

```bash
cd test-suite
./run.sh
```

See the content of `run.sh` for more versatility.

Please [report](https://github.com/NICMx/Jool/issues) any errors or queued packets you find. Please include your distro, kernel version (`uname -r`) and the tail of `dmesg` (after the "SIIT/NAT64 Jool vX.Y.Z.W module inserted" caption).

That's everything most users need to know. See below if you want to add tests to the suite.

## Preparing tests

This is what you need to know:

Adding tests to the suite right away is cumbersome; you don't want to run the entire suite when you're testing your *test*. To speed things up, you can run improvised standalone packet exchanges with the suite's translators by interacting with the following scripts (attached):

	test-suite/namespace-create.sh
		Creates a network namespace where the translator will be
		enclosed and the relevant virtual interfaces.
	test-suite/namespace-destroy.sh
		Cleans up whatever namespace-crete.sh did.
	test-suite/network-create.sh <translator>
		Prepares the test network for the relevant translator.
		<translator> can be either "siit" or "nat64".
	test-suite/network-destroy.sh <translator>
		Cleans up whatever network-crete.sh did.

So, for example, to prepare an environment to send some improvised packets to the SIIT translator, run

```bash
test-suite/namespace-create.sh
test-suite/network-create.sh siit
```

A description of the network we just created can be found in `test-suite/siit network.txt`. (TODO we need a NAT64 version too.)

You can run `ip address` here to see your channels to your "improvised" translator.

Then send some packets and see how Jool behaves (via `tcpdump`, `dmesg` and stuff):

```bash
usr/graybox send some-packet-1.pkt
usr/graybox send some-packet-2.pkt
usr/graybox send some-packet-3.pkt
```

See `man usr/graybox.7` for more documentation on what `usr/graybox` can do.

Finally, when you're done, issue the following commands to clean up:

```bash
test-suite/network-destroy.sh siit
test-suite/namespace-destroy.sh
```

## Adding improvised tests to the suite

(TODO now that I added the previous section, this is kind of obsolete and should become "how to add your improvised test to the suite.")

You need to provide:

- A "test" packet. (A packet that is sent to the translator.)
- An "expected" packet. (The packet that we expect the translator to turn the "test" packet into.)

The framework expects each packet to be found verbatim (layer 3 header, layer 4 header, payload) in a dedicated file. See examples in `test-suite/client/siit/manual`.

Assuming that there is a translator available, and the packets' addresses will be routed towards and back from it, a standalone test can be pulled off as follows:

```bash
# Start graybox.
insmod mod/graybox.ko
# Tell graybox to "expect" packet foo.pkt
usr/graybox expect add foo.pkt
# Tell graybox to send "test" packet bar.pkt
usr/graybox send bar.pkt
# Wait. Jool translates bar.pkt and graybox validates the response.
# Hopefully this should happen in less than a tenth of a second.
# I wish I had a more bulletproff and less wasteful way to do this.
# Maybe later.
# This is only for scripts. If you're typing this, you obviously don't need this
# unless you can type faster than the kernel can send packets.
sleep 0.1
# Tell graybox to stop expecting foo.
# (And any other expected packets we might have queued.)
# Only needed if you want to run more tests that involve other expected packets.
usr/graybox expect flush
# Print the results.
usr/graybox stats display
# Stop graybox.
rmmod graybox
```

## Some notes

- I don't know if the graybox kernel module is a very elegant way to do this. Perhaps raw sockets would get the job done just fine.
- The graybox userspace app has a man page; run `man ./usr/graybox.7`.
