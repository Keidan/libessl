SRC                     = essl.c
OBJ                     = $(SRC:.c=.o)
INSTALL                 = ../deploy/$(shell uname -m)
LIB	    		= libessl.so
CC         		= gcc
FLAGS             	= -Wall -W -pedantic -fPIC
DEBUG_FLAGS             = -g -O0
INC_FLAGS               = -I$(PWD)/../api
# Compiler
CFLAGS = $(DEBUG_FLAGS) $(INC_FLAGS) $(FLAGS)
# Linker
LDFLAGS = -lssl -lcrypto -lm

.SUFFIXES: .c

default: $(LIB)

all: $(LIB)


$(LIB): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -shared
	@mkdir -p $(INSTALL) 
	@mv $(LIB) $(INSTALL)

.c.o:
	echo 'Building target: $@'
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(INSTALL)/$(LIB) *~

