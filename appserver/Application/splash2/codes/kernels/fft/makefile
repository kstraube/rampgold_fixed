BUILD_DIR := /scratch/waterman/Software/build
CFLAGS = -O2 -w -I$(BUILD_DIR)/rampinclude
CC = sparc-elf-gcc
LDFLAGS = -lm -L$(BUILD_DIR)/ramplib -lpthread -lcommon

TARGET = FFT
OBJS = fft.o
MACROS = ./c.m4.ramp

x = *

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -o $(TARGET) $(LDFLAGS)

.SUFFIXES:
.SUFFIXES:	.o .c .C .h .H

.H.h:
	m4 ${MACROS} $*.H > $*.h

.C.c:
	m4 $(MACROS) $*.C > $*.c

.c.o:
	$(CC) -c $(CFLAGS) $*.c

.C.o:
	m4 $(MACROS) $*.C > $*.c
	$(CC) -c $(CFLAGS) $*.c

clean:
	-rm -f *.c *.h *.o $(TARGET)
