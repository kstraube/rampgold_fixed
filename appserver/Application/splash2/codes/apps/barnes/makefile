BUILD := ../../../../../build
include $(BUILD)/Makefile.common
TARGET = BARNES
FILES = code.C code_io.C load.C grav.C getparam.C util.C \
	code.H defs.H stdinc.H vectmath.H
CS = code.c code_io.c load.c grav.c getparam.c util.c 
OBJS = code.o code_io.o load.o grav.o getparam.o util.o
CFLAGS = -O2 -w -I$(RAMPINCLUDE)
LDFLAGS = -lm -lhart -lcommon -L$(RAMPLIB)
MACROS = c.m4.ramp
M4 = m4 -s -Ulen -Uindex

x = *

$(TARGET): $(OBJS)
	sparc-elf-gcc $(OBJS) $(CFLAGS) -o $(TARGET) $(LDFLAGS)

.SUFFIXES:
.SUFFIXES:	.o .c .C .h .H

.H.h:
	$(M4) ${MACROS} $*.H > $*.h

.C.c:
	$(M4) $(MACROS) $*.C > $*.c

.c.o:
	sparc-elf-gcc -c $(CFLAGS) $*.c

.C.o:
	$(M4) $(MACROS) $*.C > $*.c
	sparc-elf-gcc -c $(CFLAGS) $*.c

code.h: code.H defs.h
defs.h: defs.H stdinc.h vectmath.h
stdinc.h: stdinc.H 
vectmath.h : vectmath.H

code.o: code.C code.h defs.h
code_io.o: code_io.C code.h
getparam.o: getparam.C stdinc.h
grav.o: grav.C code.h
load.o: load.C code.h defs.h
util.o: util.C stdinc.h

