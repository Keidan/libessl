
all:
	@for i in $(shell find ./* -type d | sort); do \
	  cd $$i && $(MAKE) -f Makefile all && cd ..;\
	done;

clean:
	@for i in $(shell find ./* -type d | sort); do \
	  cd $$i && $(MAKE) -f Makefile clean && cd ..;\
	done;

