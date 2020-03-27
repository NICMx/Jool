# Graybox Tests

The "graybox" tests are the logical step after the unit tests. They are a bunch of packet exchanges between a custom IPv6/v4 raw packet sender and validator (named `graybox`) and an actual Jool binary.

## Compiling the test binaries

Install libnl-genl-3, then

```bash
./autogen.sh
./configure
make
```

Don't install these binaries; it's not necessary nor recommended.

## Running the test suite

Install the version of Jool you want to test, and maybe stop the network manager.

```bash
cd test-suite
sudo ./run.sh
```

See the content of `run.sh` for more versatility.

Please [report](https://github.com/NICMx/Jool/issues) any errors or queued packets you find. Please include your distro, kernel version (`uname -r`) and the tail of `dmesg` (after the "SIIT/NAT64 Jool vX.Y.Z.W module inserted" caption).

That's everything you need to know if you just want to run the tests. See below if you'd like to add tests to the suite.

## Preparing tests

This is what you need to know:

Adding tests to the suite right away is cumbersome; you don't want to run the entire thing when you're just testing your *test*. To speed things up, you can run improvised standalone packet exchanges with the suite's translators by interacting with the following scripts (in the `test-suite` folder):

	namespace-create.sh
		Creates a network namespace where the translator will be
		enclosed and the relevant virtual interfaces.
		See the output of `ip netns` and `ip link` to take a peek
		to the results.
	namespace-destroy.sh
		Reverts whatever namespace-create.sh did.
	network-create.sh <translator>
		Prepares the test network for the relevant translator.
		<translator> can be either "siit" or "nat64".
		See the output of `ip addr` to take a peek to the
		results.
	network-destroy.sh <translator>
		Reverts whatever network-create.sh did.

So, for example, to prepare an environment to send some improvised packets to the SIIT translator, run

```bash
cd test-suite
sudo ./namespace-create.sh
sudo ./network-create.sh siit
cd ..
```

A description of the network you just created can be found in `test-suite/siit network.txt`. (TODO we need a NAT64 version too.) See `ip address` too.

Then send some test packets. Evaluate results via tools such as `dmesg` (if you enabled [debug](https://github.com/NICMx/Jool/wiki/Jool's-Compilation-Options#-ddebug)) and `tcpdump`. Graybox expects test packets to be contained verbatim (from layer 3 header onwards) in a file. See examples in `test-suite/client/siit/manual`.

```bash
usr/graybox send /path/to/some-packet-1.pkt
usr/graybox send /path/to/some-packet-2.pkt
usr/graybox send /path/to/some-packet-3.pkt
```

See `man usr/graybox.7` for more documentation on what `usr/graybox` can do.

Finally, when you're done, issue the following commands to clean up:

```bash
cd test-suite
sudo ./network-destroy.sh siit
sudo ./namespace-destroy.sh
cd ..
```

## Adding your "improvised" test to the suite

For every test, you need to provide:

- A "test" packet. (A packet that is sent to the translator. It's the one you generated during the previous step.)
- An "expected" packet. (The packet that we expect the translator to turn the "test" packet into.)

Test "expected" by doing something like (assuming the namespace and the network are set)

```bash
# Tell graybox to "expect" packet foo.pkt
usr/graybox expect add /path/to/foo.pkt
# Ask graybox to send "test" packet bar.pkt
usr/graybox send /path/to/bar.pkt
# Wait. Jool translates bar.pkt and graybox validates the response.
# Hopefully this should happen in less than a tenth of a second.
# This is only for scripts. If you're typing this, you obviously don't need this
# unless you can type faster than the kernel can send packets.
sleep 0.1
# Tell graybox to stop expecting foo.
# (And any other expected packets we might have queued.)
# Only needed if you want to run more tests that involve other expected packets.
usr/graybox expect flush
# Print the results.
usr/graybox stats display
```

Place both the expected and test packets in `test-suite/client/<translator>/manual` and register them in `test-suite/client/<translator>/send.sh` ("misc" section, or make a new one).

Test the full suite and you're done. Might want to commit and upload your work to the repository.

## Some notes

- I don't know if the graybox kernel module is a very elegant way to do this. Perhaps raw sockets would get the job done just fine.
- The graybox userspace app has a man page; run `man ./usr/graybox.7`.
