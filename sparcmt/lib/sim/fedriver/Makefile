CC=gcc
CFLAGS=-O4 -fPIC -Wall -pedantic #-ansi

LIBBFD_INCLUDES=$(HOME)/sparc-linux-binutil/x86_64-unknown-linux-gnu/sparc-linux/include
LIBBFD_LIBRARY=$(HOME)/sparc-linux-binutil/x86_64-unknown-linux-gnu/sparc-linux/lib
LIBIBERTY_LIBRARY=$(HOME)/sparc-linux-binutil/lib64

check_includes=bfd.h dis-asm.h

check_libraries=libopcodes.a libbfd.a libopcodes.so libbfd.so libiberty.a

all : check_dependencies fedriver

.PHONY: check_dependencies

check_dependencies:
	@list='$(check_includes) $(check_libraries) libiberty.a'; \
	for p in $$list; do \
	   if test ! -e $(LIBBFD_INCLUDES)/$$p && test ! -e $(LIBBFD_LIBRARY)/$$p && test ! -e $(LIBIBERTY_LIBRARY)/$$p; then  \
	   	echo "missing $(LIBBFD_INCLUDES)/$$p"; \
		echo "please crosscompile libbfd & libopcodes"; \
		exit 1; \
	   fi; \
	done; \

	@if test ! -e "fedriver.h"; then \
		echo "please use 'vlog -dpiheader' to generate fedriver.h"; exit 1; \
	fi; \

	@if test -z "$(MTI_HOME)"; then \
		echo "modelsim is not correctly installed and MTI_HOME is undefined"; exit 1; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -I. -I$(MTI_HOME)/include -I$(LIBBFD_INCLUDES) -c $<

fedriver: fedriver.o socket.o
#	$(CC) -shared -Wl,-Bsymbolic -Wl,-export-dynamic -o fedriver.so $< $(LIBBFD_LIBRARY)/libopcodes.a $(LIBBFD_LIBRARY)/libbfd.a $(LIBIBERTY_LIBRARY)/libiberty.a


	$(CC) -shared -Wl,-Bsymbolic -Wl,-export-dynamic -o fedriver.so fedriver.o socket.o

test_disas: test_disas.o
	$(CC) -L$(LIBBFD_LIBRARY) -lopcodes -L$(LIBBFD_LIBRARY) -lbfd -Wl,-rpath $(LIBBFD_LIBRARY) -o test_disas $< $(LIBIBERTY_LIBRARY)/libiberty.a

clean:
	-rm -f *.o fedriver.so test_fedriver



