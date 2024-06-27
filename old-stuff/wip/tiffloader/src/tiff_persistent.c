#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "loadtiff.h"

__AFL_FUZZ_INIT();

int main() {

    int ret = 0;
    int fd;
    int width, height;
    unsigned char *data;
    int format;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    int len = 0;
    FILE *fp = NULL;
  __AFL_INIT();

  while (__AFL_LOOP(10000)) {

      fd = open("./input_persistent.tiff", O_RDWR | O_CREAT, 0666);
      if (fd == -1) {
          fprintf(stderr, "fd: error\n");
          exit(-1);
      }
      len = __AFL_FUZZ_TESTCASE_LEN;
      write(fd, buf, len);
      close(fd);

      fp = fopen("./input_persistent.tiff", "rb");
      if(!fp) {
          fprintf(stderr, "ERROR\n");
          continue;
      } 
      data = floadtiff(fp, &width, &height, &format);
      fclose(fp);

      if(data == 0) {
          fprintf(stderr, "TIFF file unreadable\n");
      }

  }
  return 0;
}
