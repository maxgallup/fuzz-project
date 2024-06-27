#include <stdio.h>
#include <stdlib.h>
#include "gifdec.h"
#include <unistd.h>
#include <sys/fcntl.h>

int run(char *buffer, int len) {
    int ret = 0;
    int fd;
    uint32_t count = 0;
    uint8_t *frame;
    gd_GIF *gif = NULL;

    
    fd = open("./input_frida_persistent.gif", O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        fprintf(stderr, "fd: error\n");
        exit(-1);
    }
    write(fd, buffer, len);
    close(fd);
    
    gif = gd_open_gif("./input_frida_persistent.gif");
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
    remove("./input_frida_persistent.gif");
    puts("all good");
    return 0;
}

int main(int argc, char *argv[]) {
    char buffer[256];
    run(buffer, 256);
    return 0;
}

