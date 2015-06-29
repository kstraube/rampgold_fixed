#
# Makefile for adpcm and test programs
# -------------------

#####################################################################
# Added by C. Lee.
#
# On Sun machines, gcc need to be informed whether the machines have
# integer multipliers by specifying this option: -mv8.
#
# Also, on Sun machines, in order to use the SPIXTOOLS and SHADE,
# uncomment this option: -static.
#
#CC = gcc
#LFLAGS = -mv8
# LFLAGS = $(LFLAGS) -static
#
# End of addition
######################################################################
CC = sparc-elf-gcc
CFLAGS = -lc -lsys -mcpu=v8

# May need this on a sun:
# CFLAGS=-O -I/usr/demo/SOUND

srcdir = .
VPATH = .:$(srcdir)

ALLSRC=README adpcm.2 Makefile adpcm.h libst.h adpcm.c timing.c rawcaudio.c \
	rawdaudio.c suncaudio.c sgicaudio.c sgidaudio.c hello.adpcm.uu

all: adpcm.o rawcaudio rawdaudio
#	cp rawcaudio rawdaudio timing ../bin/.

sgi: all sgicaudio sgidaudio

sun: all suncaudio sundaudio

adpcm.o: adpcm.h

suncaudio: suncaudio.o adpcm.o
	$(CC) adpcm.o suncaudio.o -o suncaudio -L/usr/demo/SOUND -laudio

sundaudio: suncaudio
	cp suncaudio sundaudio

sgicaudio: sgicaudio.o adpcm.o
	$(CC) sgicaudio.o adpcm.o -o sgicaudio -laudiofile -lm

sgidaudio: sgidaudio.o adpcm.o
	$(CC) sgidaudio.o adpcm.o -o sgidaudio -laudiofile -lm

rawcaudio: rawcaudio.o adpcm.o
	$(CC) rawcaudio.o adpcm.o -o rawcaudio $(CFLAGS)

rawdaudio: rawdaudio.o adpcm.o
	$(CC) rawdaudio.o adpcm.o -o rawdaudio $(CFLAGS)

timing: timing.o adpcm.o
	$(CC) timing.o adpcm.o -o timing -liberty $(CFLAGS)

adpcm.shar: $(ALLSRC)
	shar $(ALLSRC) > adpcm.shar

# Added by C. Lee
clean:
	rm -f *.o ; rm rawcaudio rawdaudio ; rm -f ../bin/*
