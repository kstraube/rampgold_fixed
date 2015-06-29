RAMP_SOFTWARE_DIR := ../../../../../../Software

CC=gcc
CXX=g++
CFLAGS=-O4 -fPIC -Wall -I$(RAMP_SOFTWARE_DIR)
LDFLAGS=-L$(RAMP_SOFTWARE_DIR)/build/lib -lcgold-debug -lappserver -lcommon

LIBBFD_INCLUDES=$(HOME)/sparc-linux-binutil/x86_64-unknown-linux-gnu/sparc-linux/include

all : check_dependencies tm_test

.PHONY: check_dependencies

check_dependencies:
	@if test ! -e "tm_test.h"; then \
		echo "please use 'vlog -dpiheader' to generate tm_test.h"; exit 1; \
	fi; \

	@if test -z "$(MTI_HOME)"; then \
		echo "modelsim is not correctly installed and MTI_HOME is undefined"; exit 1; \
	fi

%.o: %.cpp
	$(CXX) $(CFLAGS) -I. -I$(MTI_HOME)/include -I$(LIBBFD_INCLUDES) -c $<

%.o: %.c
	$(CC) $(CFLAGS) -I. -I$(MTI_HOME)/include -I$(LIBBFD_INCLUDES) -c $<

tm_test: tm_test.o foo.o 
	$(CXX) -shared -Wl,-Bsymbolic -Wl,-export-dynamic -o tm_test.so tm_test.o foo.o $(LDFLAGS)
	
clean:
	rm -f *.o tm_test.so
