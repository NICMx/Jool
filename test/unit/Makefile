# Layer 0 (basic testing framework)
PROJECTS += framework

# Layer 1 tests (utils)
PROJECTS += addr
PROJECTS += iterator
PROJECTS += pkt
PROJECTS += rbtree
PROJECTS += rfc6052
PROJECTS += rfc6056
PROJECTS += types
PROJECTS += mapt

# Layer 2 tests (tables)
PROJECTS += eamt
PROJECTS += bibtable
PROJECTS += sessiontable

# Layer 3 tests (dbs)
PROJECTS += pool4db
PROJECTS += bibdb
PROJECTS += sessiondb

# Layer 4 tests (utils that depend on the dbs)
#PROJECTS += joolns

# Layer 5 tests (translation steps)
PROJECTS += filtering
PROJECTS += translate

# Layer 6 test (global translation)
#PROJECTS += page # Problematic


CLEANPROJECTS = $(patsubst %,%.clean,$(PROJECTS))


all: $(PROJECTS)

$(PROJECTS):
	$(MAKE) -C $@

clean: $(CLEANPROJECTS)

$(CLEANPROJECTS):
	$(MAKE) -C $(@:.clean=) clean

.PHONY: clean $(PROJECTS) $(CLEANPROJECTS)
