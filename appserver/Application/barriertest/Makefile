#CC := sparc-elf-gcc -O3 -I../../build/rampinclude -L../../build/ramplib
#LDFLAGS := -lhart -lcommon

CC := gcc -g -O3 -I../../build/include -L../../build/lib
LDFLAGS := -lhart -lcommon -lnuma -lpthread

barriertest: main.c
	$(CC) -o main main.c $(LDFLAGS)
