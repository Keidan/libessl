SRC                     = base64.c
OBJ                     = $(SRC:.c=.o)
BINTEST    		= base64.elf
CC         		= gcc
FLAGS  		        = -Wall -W -pedantic -Wformat=0
DEBUG_FLAGS             = -g -O0
INC_FLAGS               = -I$(PWD)/../../api

# Compiler
CFLAGS = $(DEBUG_FLAGS) $(INC_FLAGS) $(FLAGS)

# Linker
LDFLAGS = -lessl -L../../deploy/$(shell uname -m)

.SUFFIXES: .c

default: $(LIB)

all: $(BINTEST)


$(BINTEST): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o:%.c 
	echo 'Building target: $@'
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BINTEST)
