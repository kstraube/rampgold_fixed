CC=gcc
CFLAGS=-O4 -fPIC -Wall -pedantic #-ansi

LIBBFD_INCLUDES=$(HOME)/sparc-linux-binutil/x86_64-unknown-linux-gnu/sparc-linux/include

all : check_dependencies bee3_tester

.PHONY: check_dependencies

check_dependencies:
	@if test ! -e "bee3_tester.h"; then \
		echo "please use 'vlog -dpiheader' to generate bee3_tester.h"; exit 1; \
	fi; \

	@if test -z "$(MTI_HOME)"; then \
		echo "modelsim is not correctly installed and MTI_HOME is undefined"; exit 1; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -I. -I$(MTI_HOME)/include -I$(LIBBFD_INCLUDES) -c $<

bee3_tester: bee3_tester.o

	$(CC) -shared -Wl,-Bsymbolic -Wl,-export-dynamic -o bee3_tester.so bee3_tester.o 

clean:
	rm -f *.o bee3_tester.so

