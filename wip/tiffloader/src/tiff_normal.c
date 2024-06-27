#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "loadtiff.h"

int main(int argc, char *argv[]) {

    int ret = 0;
    int fd;
    int width, height;
    unsigned char *data;
    int format;
    int len = 0;
    FILE *fp = NULL;

    fp = fopen(argv[1], "rb");
    if(!fp) {
        fprintf(stderr, "ERROR opening file\n");
        exit(-1);
    } 
    data = floadtiff(fp, &width, &height, &format);
    fclose(fp);

    if(data == 0) {
        fprintf(stderr, "TIFF file unreadable\n");
        exit(-1);
    }

  return 0;
}
