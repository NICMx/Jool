# Layer 1 tests (utils)
PROJECTS += addr
PROJECTS += hashtable
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
PROJECTS += fragdb
PROJECTS += pool4db
PROJECTS += bibdb
PROJECTS += sessiondb

# Layer 4 tests
PROJECTS += joolns

# Layer 5 tests (translation steps)
PROJECTS += filtering
PROJECTS += translate

# Layer 6 test (global translation)
PROJECTS += page


CLEANPROJECTS = $(patsubst %,%.clean,$(PROJECTS))


all: $(PROJECTS)

$(PROJECTS):
	$(MAKE) -C $@

clean: $(CLEANPROJECTS)
	find ../../mod -type f -name "*.o" -delete

$(CLEANPROJECTS):
	$(MAKE) -C $(@:.clean=) clean

.PHONY: clean $(PROJECTS) $(CLEANPROJECTS)
