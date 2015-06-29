CC=gcc
CFLAGS=-O4 -fPIC -Wall -pedantic -std=gnu99 #-ansi

LIBBFD_INCLUDES=$(HOME)/sparc-linux-binutil/x86_64-unknown-linux-gnu/sparc-linux/include

all : check_dependencies mac_fedriver

.PHONY: check_dependencies

check_dependencies:
	@if test ! -e "mac_fedriver.h"; then \
		echo "please use 'vlog -dpiheader' to generate mac_fedriver.h"; exit 1; \
	fi; \

	@if test -z "$(MTI_HOME)"; then \
		echo "modelsim is not correctly installed and MTI_HOME is undefined"; exit 1; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -I. -I$(MTI_HOME)/include -I$(LIBBFD_INCLUDES) -c $<

mac_fedriver: mac_fedriver.o socket.o

	$(CC) -shared -Wl,-Bsymbolic -Wl,-export-dynamic -o mac_fedriver.so mac_fedriver.o socket.o

clean:
	-rm -f *.o mac_fedriver.so

