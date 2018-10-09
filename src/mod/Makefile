PROJECTS = siit nat64
OTHER_TARGETS = modules modules_install clean debug


all: $(PROJECTS)
	# Running the dependencies is enough.
$(PROJECTS):
	$(MAKE) -C $@
$(OTHER_TARGETS):
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) $@;)
install:
	# Don't want to execute depmod twice; it takes too long.
	$(foreach dir, $(PROJECTS), $(MAKE) -C $(dir) modules_install;)
	depmod


.PHONY: $(PROJECTS) $(OTHER_TARGETS) install
