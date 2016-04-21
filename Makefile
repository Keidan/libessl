.PHONY : lib demo clean all

all: lib demo

lib:
	cd lib && $(MAKE) -f Makefile all

demo:
	cd demo && $(MAKE) -f Makefile all

clean:
	cd lib && $(MAKE) -f Makefile clean
	cd demo && $(MAKE) -f Makefile clean
	find . -type f -name "*~" -exec rm -f {} \;


exec:
	@for i in $(shell find ./demo -name *.elf); do \
	  echo "Execute $$(basename $$i .elf):"; \
	  LD_LIBRARY_PATH=./deploy/$$(uname -m) ./$$i;\
	  echo ""; \
	done
