# Layer 1 tests (utils)
PROJECTS += addr
PROJECTS += iterator
PROJECTS += pkt
PROJECTS += rbtree
PROJECTS += rfc6052
PROJECTS += rfc6056
PROJECTS += types

# Layer 2 tests (tables)
PROJECTS += eamt
PROJECTS += bibtable
PROJECTS += sessiontable

# Layer 3 tests (dbs)
PROJECTS += pool4db
PROJECTS += bibdb
PROJECTS += sessiondb
PROJECTS += joold

# Layer 4 tests (utils that depend on the dbs)
#PROJECTS += joolns

# Layer 5 tests (translation steps)
PROJECTS += filtering
PROJECTS += translate

# Layer 6 test (global translation)
PROJECTS += page


CLEANPROJECTS = $(patsubst %,%.clean,$(PROJECTS))


all: $(PROJECTS)

$(PROJECTS):
	$(MAKE) -C $@

# Kbuild can create object files outside of the module's directory (as defined
# by the `-objs` variables), but as it turns out, it doesn't remove them.
# This is a problem for `clean` targets.
#
# There used to be a command in this target to work around that. It looked
# somewhat like this:
#
# 	find ../../src -type f -name "*.o" -delete
#
# But it had several drawbacks:
#
# 1. It indiscriminately removed all `.o` files in `src/`. (Even object files
#    that had nothing to do with unit testing.)
# 2. It only ran during this makefile. The individual PROJECTS didn't have it,
#    and thus would leave the garbage around when individually `clean`d.
# 3. It only deleted *object* files.
#
# That last one is a major problem. I don't know if it has always been like
# this, but Kbuild now generates additional garbage. This is not future-proof.
#
# I think the right thing to do would be to stop referencing other directories.
# The only way to do this off the top of my head would be to #include .c's in
# the unit tests, rather than compile them as separate object files.
# Fort already does this, and it works decently there.
#
# For the time being, rely on `deconf.sh` (in the root of the project).
clean: $(CLEANPROJECTS)

$(CLEANPROJECTS):
	$(MAKE) -C $(@:.clean=) clean

.PHONY: clean $(PROJECTS) $(CLEANPROJECTS)
