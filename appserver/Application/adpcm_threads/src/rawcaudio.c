/* testc - Test adpcm coder */

#include "adpcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

struct adpcm_state state;

#define NSAMPLES 1000

#define min(a,b) ((a)>(b)?(b):(a))

main() {
    int n;
    int rfd,wfd;
    short* readbuf;
    char* writebuf;
    int readlen;
    int writelen;
    int readcur;
    int writecur;

    rfd=open("input.pcm", O_RDONLY);
    if (rfd == -1) {
        printf("file input error!\n");
        exit(-1);
    }
    wfd=open("output_tst.adpcm", O_CREAT|O_WRONLY);
    if (wfd == -1) {
        printf("file output error!\n");
        close(rfd);
        exit(-1);
    }

    readbuf = 0x3000000;
    writebuf = 0x4000000;
    readlen = 0;
    writelen = 0;

    while(1) {
        n = read(rfd, &readbuf[readlen], NSAMPLES*2);
        if ( n < 0 ) {
            perror("input file");
            exit(1);
        } else if ( n == 0 ) {
            break;
        }
        readlen += n;
    }

    readcur = 0;
    writecur = 0;

    while(readcur<readlen) {
        n = min(NSAMPLES*2,readlen-readcur);
        adpcm_coder(&readbuf[readcur], &writebuf[writecur], n/2, &state);
        readcur += n;
        writecur += n/4;
    }

    write(wfd, writebuf, writecur);

    close(rfd);
    close(wfd);
    fprintf(stderr, "Final valprev=%d, index=%d\n",
            state.valprev, state.index);
    exit(0);
}
