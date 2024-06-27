#include <stdio.h>
#include <stdlib.h>
#include "gifdec.h"
#include <unistd.h>
#include <sys/fcntl.h>

int run(char *filename) {
    int ret = 0;
    int fd;
    uint32_t count = 0;
    uint8_t *frame;
    gd_GIF *gif = NULL;

    gif = gd_open_gif(filename);
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
    puts("all good");
    return 0;
}

int main(int argc, char *argv[]) {
    run(argv[1]);
    return 0;
}

