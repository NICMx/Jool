AUTOMAKE_OPTIONS = foreign

# dpkg-buildpackage uses SUBDIRS during the package build.
#
# We don't want dpkg-buildpackage to build src/mod, because any kernel update
# will render the resulting binaries obsolete and useless. What we want is to
# ship the source code. Once installed, DKMS will automatically recompile it
# every time the kernel is updated.
#
# So we want to include src/mod in the distribution, but omit its compilation by
# default. This arrangement of SUBDIRS and DIST_SUBDIRS does that.
SUBDIRS = src/common src/usr
DIST_SUBDIRS = src/common src/mod src/usr

# Needed by libtoolize. (Othewise autoreconf complains.)
ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST=dkms.conf README.md
