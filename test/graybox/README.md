# Graybox Tests Run

This directory contains the scripts needed to run the graybox test suite on [Jool (SIIT and NAT64)](https://www.jool.mx/en/intro-xlat.html).

In order to run the test suite, you need at least two linux machines running (either physical or virtual) each with two ethernet interfaces. One will work as the translator and the other will run the actual tests. 

After that, a successful installation of [Jool's kernel module](https://nicmx.github.io/Jool/en/install-mod.html) and [Jool's userspace application](https://nicmx.github.io/Jool/en/install-usr.html) are required in the translator machine. 

Lastly you will need to:

1. Compile the graybox kernel module, then mount it in the translator machine.
2. Compile the graybox application in the client machine.
3. Set up the environment.
4. Run the test suite.

*Note:* $JOOL is your Jool directory, wether its Jool-<version> or Jool-master

### Compiling graybox kernel module
In the translator machine, use Kbuild to compile and install the graybox kernel module. 

```bash
cd $JOOL/test/graybox/mod
sudo make
sudo make modules_install
```

I recommend running `depmod` just to make sure modprobe will actually insert the module when invoked.

### Compiling usr/graybox
In the client machine, follow the next steps:

```bash
cd $JOOL/test/graybox/usr
sudo make
sudo make install
```

### Setup the environment

##### Translator
Because you have two machines in a server-client configuration, you need to set both up.

For the translator, configuration scripts are located at `$JOOL/test/graybox/test-suite/xlat`. You only one of these scripts:
```bash
./nat64.sh
./siit.sh
```

**Note:** If your interfaces you intend to use are not named eth0 and eth1, please adjust the script.

Please note that packets translated are sent with specific IP addresses, and are asserted as is, so there's no room to modify IP addresses.

##### Client
For the client, run either one of the next scripts 

```bash
$JOOL/test/graybox/test-suite/client/nat64/setup.sh
```
```bash
$JOOL/test/graybox/test-suite/client/siit/setup.sh
``` 
depending on the mode you want to test.

### Running the test-suite
In order to run the test suite, run either one of the next script:`

```bash
cd $JOOL/test/graybox/test-suite/client/nat64/
./send.sh
```
```bash
cd $JOOL/test/graybox/test-suite/client/siit/
./send.sh
```
matching the mode you setted up in the configuration.

### Running the test suite in a single machine using `netns`
If you wish to do so, you can also use a single machine as both the client and the translator by encasing Jool in a user netns.

To do this, you need to compile both the kernel module and the graybox script in the same machine (follow steps 1 and 2 in the same machine).

Afterwards, you can use one of the scripts located at `$JOOL/test/graybox/test-suite/xlat`:

```bash
./nat64-netns.sh
./siit-netns.sh
```

I don't think you need to modify interfaces name unless you already have one named `wire0` or `wire1`. Running any of these scripts also modprobes graybox (just as the client setup scrits do).

Now, just follow step 4 and you're done.

Lastly, if you wish to run everything, run `$JOOL/test/graybox/test-suite/run-netns-graybox.sh`.

### Cleanup
After you're done running test-suite, execute `end.sh` (or `end-netns.sh` if using `netns`) located at the next directories (for client, you only need to clean whichever mode you ran):

```bash
$JOOL/test/graybox/test-suite/client/nat64/
$JOOL/test/graybox/test-suite/client/siit/
$JOOL/test/graybox/test-suite/xlat/
```

***Please note:*** Alberto Leiva has notified me that in the case Jool crashes, the whole machine might crash, even if Jool is inside a user netns; therefor it is recommended to use another virtual machine to host Jool.