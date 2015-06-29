BINARIES := memtest memtest-x86

all: $(BINARIES)

memtest: memtest.c
	sparc-ros-gcc -O2 -static -DMEMTEST_ALL -o memtest memtest.c -I../../build/rampinclude -L../../build/ramplib -lhart
	cp memtest ../../build/rampbin

memtest-x86: memtest.c
	gcc -O2 -o memtest-x86 -DMEMTEST_ALL memtest.c -I../../build/include -L../../build/lib -lhart -lpthread

clean:
	-rm -f $(BINARIES)
