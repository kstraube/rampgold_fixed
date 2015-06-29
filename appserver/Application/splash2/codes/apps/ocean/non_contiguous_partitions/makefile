BUILD := ../../../../../../build
include $(BUILD)/Makefile.common
TARGET = OCEAN
OBJS = main.o jacobcalc.o laplacalc.o \
	slave1.o slave2.o multi.o
CFLAGS = -O2 -w -I$(RAMPINCLUDE)
LDFLAGS = -lm -lhart -lcommon -L$(RAMPLIB)
MACROS = c.m4.ramp

x = *

$(TARGET): $(OBJS)
	sparc-elf-gcc $(OBJS) -o $(TARGET) $(LDFLAGS)

.SUFFIXES:
.SUFFIXES:	.o .c .C .h .H

.H.h: 
	m4 ${MACROS} $*.H > $*.h

.C.c: 
	m4 $(MACROS) $*.C > $*.c

.c.o: 
	sparc-elf-gcc -c $(CFLAGS) $*.c

.C.o: 
	m4 $(MACROS) $*.C > $*.c
	sparc-elf-gcc -c $(CFLAGS) $*.c

decs.h: decs.H
jacobcalc.c: decs.h
main.c: decs.h
slave1.c: decs.h
laplacalc.c: decs.h
multi.c : decs.h
slave2.c: decs.h

