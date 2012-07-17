all:
	cd tools && $(MAKE) $@

install: dummy
	cd tools && $(MAKE) $@

clean:
	cd tools && $(MAKE) $@

dummy:
