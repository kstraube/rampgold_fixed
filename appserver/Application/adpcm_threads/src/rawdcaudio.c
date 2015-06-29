/* testd - Test adpcm decoder */

#include "adpcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

struct adpcm_state state_decode;
struct adpcm_state state_encode;

#define NSAMPLES 1000

#define min(a,b) ((a)>(b)?(b):(a))

char* readbuf_decode;
short* writebuf_decode;
int readlen_decode;
int writecur_decode;

short* readbuf_encode;
char* writebuf_encode;
int readlen_encode;
int writecur_encode;

int barrier;

void hardthread(int destid, void (*funcp)(void*), void* arg)
{
__asm__(""
"   set 99,%g1\n"
"   mov %i0,%o0\n"
"   mov %i1,%o1\n"
"   mov %i2,%o2\n"
"   ta 8\n");
}

void read_decode()
{
    int rfd;
    int n;

    rfd=open("input.adpcm", O_RDONLY);
    if (rfd == -1) {
        printf("file input error!\n");
        exit(-1);
    }

    readlen_decode = 0;

    while(1) {
        n = read(rfd, &readbuf_decode[readlen_decode], NSAMPLES/2);
        if ( n < 0 ) {
            perror("input file");
            exit(1);
        } else if ( n == 0 ) {
            break;
        }
        readlen_decode += n;
    }

    close(rfd);
}

void decode()
{
    int n;
    int readcur;

    readcur = 0;
    writecur_decode = 0;

    while(readcur<readlen_decode) {
        n = min(NSAMPLES/2,readlen_decode-readcur);
        adpcm_decoder(&readbuf_decode[readcur], &writebuf_decode[writecur_decode], n*2, &state_decode);
        readcur+=n;
        writecur_decode+=n*2;
    }
}

void write_decode()
{
    int wfd;

    wfd=open("output_tst.pcm", O_CREAT|O_WRONLY, 0666);
    if (wfd == -1) {
        printf("file output error!\n");
        exit(-1);
    }
    write(wfd, writebuf_decode, writecur_decode*2);
    close(wfd);

    fprintf(stderr, "(decode) Final valprev=%d, index=%d\n",
            state_decode.valprev, state_decode.index);
}

void read_encode()
{
    int rfd;
    int n;

    rfd=open("input.pcm", O_RDONLY);
    if (rfd == -1) {
        printf("file input error!\n");
        exit(-1);
    }

    readlen_encode = 0;

    while(1) {
        n = read(rfd, &readbuf_encode[readlen_encode], NSAMPLES*2);
        if ( n < 0 ) {
            perror("input file");
            exit(1);
        } else if ( n == 0 ) {
            break;
        }
        readlen_encode += n;
    }

    close(rfd);
}

void encode()
{
    int n;
    int readcur;

    readcur = 0;
    writecur_encode = 0;

    while(readcur<readlen_encode) {
        n = min(NSAMPLES*2,readlen_encode-readcur);
        adpcm_coder(&readbuf_encode[readcur], &writebuf_encode[writecur_encode], n/2, &state_encode);
        readcur += n;
        writecur_encode += n/4;
    }

    barrier = 1;
}

void write_encode()
{
    int wfd;

    wfd=open("output_tst.adpcm", O_CREAT|O_WRONLY, 0666);
    if (wfd == -1) {
        printf("file output error!\n");
        exit(-1);
    }
    write(wfd, writebuf_encode, writecur_encode);
    close(wfd);

    fprintf(stderr, "(encode) Final valprev=%d, index=%d\n",
            state_encode.valprev, state_encode.index);
}

main() {
    readbuf_decode = (char*)malloc(1024*1024*sizeof(char));
    writebuf_decode = (short*)malloc(1024*1024*sizeof(short));
    readbuf_encode = (short*)malloc(1024*1024*sizeof(short));
    writebuf_encode = (char*)malloc(1024*1024*sizeof(char));

    read_decode();
    read_encode();

    barrier = 0;

    decode();
    hardthread(1, &encode, NULL);

    while (!barrier) ;

    write_decode();
    write_encode();

    exit(0);
}
