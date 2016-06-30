.PHONY : lib demo clean all help

all: lib demo

help:
	@echo "make help: Print this help"
	@echo "make all: Compile all the sources"
	@echo "make: Compile all the sources"
	@echo "make lib: Compile the library"
	@echo "make demo: Compile the demos"
	@echo "make clean: Clean the compiled files"
	@echo "make exec: Execute the demos"

lib:
	cd lib && $(MAKE) -f Makefile all

demo:
	cd demo && $(MAKE) -f Makefile all

clean:
	cd lib && $(MAKE) -f Makefile clean
	cd demo && $(MAKE) -f Makefile clean
	find . -type f -name "*~" -exec rm -f {} \;

exec:
	@for i in $(shell find ./demo -name *.elf | sort); do \
	  echo "Execute $$(basename $$i .elf):"; \
	  cd $$(dirname $$i); \
	  (LD_LIBRARY_PATH=../../deploy/$$(uname -m) ./$$(basename $$i) &);\
	  cd -;\
	  echo ""; \
	done
