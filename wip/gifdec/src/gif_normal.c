#include <stdio.h>
#include <stdlib.h>
#include "gifdec.h"
#include <unistd.h>
#include <sys/fcntl.h>

__AFL_FUZZ_INIT();

int main(int argc, char *argv[]) {

  __AFL_INIT();

    int ret = 0;
    int fd;
    uint32_t count = 0;
    uint8_t *frame;
    gd_GIF *gif = NULL;
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    int len = 0;

    while (__AFL_LOOP(10000)) {
        
        fd = open("./input_normal.gif", O_RDWR | O_CREAT, 0666);
        if (fd == -1) {
            fprintf(stderr, "fd: error\n");
            exit(-1);
        }
        len = __AFL_FUZZ_TESTCASE_LEN;
        write(fd, buf, len);
        close(fd);

        gif = gd_open_gif("./input_normal.gif");
        if (gif == NULL) {
            fprintf(stderr, "gif: open_gif error\n");
            exit(-1);
        }
        frame = malloc(gif->width * gif->height * 3);
        if (!frame) {
            fprintf(stderr, "gif: could not allocate frame\n");
            exit(-2);
        }
        while (1) {
           ret = gd_get_frame(gif);
           if (ret == -1) {
               fprintf(stderr, "gif: get frame error\n");
               exit(-3);
           }
           gd_render_frame(gif, frame);
           if (ret == 0) {
               gd_rewind(gif);
               count++;
           }
           if (count == 2) {
               break;
           }
        }
        free(frame);
        remove("./input_normal.gif");
    }
    return 0;
}

