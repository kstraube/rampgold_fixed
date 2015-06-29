BUILD := ../../build
include $(BUILD)/Makefile.common

all: $(RAMPBIN)/hanoi

$(RAMPBIN)/hanoi: hanoi.c small.scr
	sparc-elf-gcc -O3 -o $(RAMPBIN)/hanoi -I../.. -L$(RAMPLIB) hanoi.c ../../Common/itoa.c -lhart -lc -lsys -Wl,-T,small.scr -mcpu=v8

clean:
	-rm $(RAMPBIN)/hanoi
