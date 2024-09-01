PROJECTS = common siit nat64 mapt
OTHER_TARGETS = modules modules_install clean debug


all: $(PROJECTS)
	# Running the dependencies is enough.
$(PROJECTS):
	$(MAKE) -C $@
$(OTHER_TARGETS):
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) $@;)
install:
	# Don't want to execute depmod four times; it takes too long.
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) modules_install;)
	/sbin/depmod

distclean maintainer-clean:
	find . -type f -a \! \( -name \*.h -o -name \*.c -o -name Makefile -o -name Kbuild \) -print0 | xargs -0r rm
	find . -type f -a -name \*.mod.c -print0 | xargs -0r rm

# This target is needed to generate the upstream tarball.
# It's not a standard Kbuild target.
distdir:
	mkdir -p ${distdir}
	cp -r * ${distdir}

.PHONY: $(PROJECTS) $(OTHER_TARGETS) install dist distclean maintainer-clean
