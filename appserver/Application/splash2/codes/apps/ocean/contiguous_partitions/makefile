BUILD_DIR := /scratch/waterman/Software/build

TARGET = OCEAN
OBJS = main.o jacobcalc.o jacobcalc2.o laplacalc.o \
	slave1.o slave2.o multi.o linkup.o subblock.o 
CFLAGS = -O2 -w
#CFLAGS = -O2 -Olimit 2000 -w 
GCC = sparc-ros-gcc
LDFLAGS = -lm
MACROS = c.m4.ramp

x = *

$(TARGET): $(OBJS)
	$(GCC) $(OBJS) -o $(TARGET) $(LDFLAGS)

.SUFFIXES:
.SUFFIXES:	.o .c .C .h .H

.H.h: 
	m4 ${MACROS} $*.H > $*.h

.C.c: 
	m4 $(MACROS) $*.C > $*.c

.c.o: 
	$(GCC) -c $(CFLAGS) $*.c

.C.o: 
	m4 $(MACROS) $*.C > $*.c
	$(GCC) -c $(CFLAGS) $*.c

clean:
	-rm -f *.c *.o *.h OCEAN

decs.h: decs.H
myprintf.h: myprintf.H
peterson.h: peterson.H
jacobcalc.c: decs.h myprintf.h peterson.h
linkup.c: decs.h myprintf.h peterson.h
slave1.c: decs.h myprintf.h peterson.h
jacobcalc2.c: decs.h myprintf.h peterson.h
main.c: decs.h myprintf.h peterson.h
slave2.c: decs.h myprintf.h peterson.h
laplacalc.c: decs.h myprintf.h peterson.h
multi.c: decs.h myprintf.h peterson.h
subblock.c: decs.h myprintf.h peterson.h

