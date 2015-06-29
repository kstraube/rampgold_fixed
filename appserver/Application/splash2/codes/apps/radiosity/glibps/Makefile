# 
#  CS348C  Radiosity     Device independent graphics package GLIB.
#                        SUN/Xview version makefile
#
#

CC = sparc-elf-gcc
OBJS   = glibps.o
TARGET = glibps.a

INCLUDE_DIRS =

#CCOPT  = -O -float
CCOPT  = -O 
CFLAGS = $(CCOPT) $(CCDEFS) $(INCLUDE_DIRS)
LDFLAGS =  -lm


all:	$(TARGET)

clean:
	touch dummy~
	rm -f core *.o *~ $(TARGET)

lint:
	lint $(INCLUDE_DIRS) $(SRCS)


$(TARGET): $(OBJS)
	sparc-elf-ar crv $(TARGET) $(OBJS)
#	ranlib $(TARGET)

testlib:
	sparc-elf-gcc -g -o testlib testlib.c $(TARGET) $(LDFLAGS)

