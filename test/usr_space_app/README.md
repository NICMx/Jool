# Userspace Application Tests

Unit tests for the userspace applications.

1. Compile and install Jool (kernel modules and userspace applications)
3. Run each one of the scripts inside this directory.

	$ for nn in `ls 4_*.sh`; do ./$nn; done

The tests assume that Jool hasn't been modprobed. They will also remove Jool once they are done.
