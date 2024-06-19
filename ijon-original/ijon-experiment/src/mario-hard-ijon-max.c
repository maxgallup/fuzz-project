// The maze demo is taken from Felipe Andres Manzano's blog:
// http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
//
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#define H 6
#define W 93
char maze[H][W] = { "+-------------------------------------------------------------------------------------------+",
                    "|      T   T       T        TTTT                    TTTTT              T   T   T            |",
                    "|      T   T                 TTTT             T      TTT      T        T   T       T        |",
                    "|          T    -- T   --+    TTTT  ----+    TTT      T      TTT       T       T   T        |",
                    "|      T           T    TT             TT   TTTTT           TTTTT          T   T   T       #|",
                    "+------------TT-----------------------------------------------------------------------------+" };
void draw ()
{
    int i, j;
    for (i = 0; i < H; i++)
      {
          for (j = 0; j < W; j++)
                  printf ("%c", maze[i][j]);
          printf ("\n");
      }
    printf ("\n");
}

void win() {
    printf("win!");
    assert(0);
}


int main (int argc, char *argv[])
{
    int x, y;
    int failed_attempts = 0;
     //Player position
    int ox, oy;   //Old player position
    int i = 0;    //Iteration number
#define ITERS 512
    char program[ITERS];
    x = 1;
    y = 4;
    maze[y][x]='X';
    draw();
    read(0,program,ITERS);

    while(i < ITERS) {

        // Uncomment this for playing it live in a terminal
        // read(0, &program[i], 1);
        maze[y][x]=' '; 

        ox = x;    //Save old player position
        oy = y;

        IJON_MAX(y);

        switch (program[i]) {
            case 'w':
                y--;
                break;
            case 's':
                y++;
                break;
            case 'a':
                x--;
                break;
            case 'd':
                x++;
                break;
            // uncomment this to play live in the terminal
            case '\n':
                continue;
            default:
                failed_attempts++;
                if (failed_attempts >= 5) {
                    exit(-1);
                }
                continue;
        }


        switch (maze[y][x]) {
            case '#': // win
                win();
                break;
            case ' ': // ok to move
                break;
            case '-': // don't move
                x = ox;
                y = oy;
                break;
            case '|': // don't move
                x = ox;
                y = oy;
                break;
            case '+': // don't move
                x = ox;
                y = oy;
                break;
            case 'T': // trap means we lose the game
                exit(-1);
                break;
        }

        // simulate gravity
        if ((maze[y+1][x] == ' ' || maze[y+1][x] == '#') && program[i] != 'w') {
            y++;
        }

        if (maze[y][x] == '#') {
            win();
        }

        maze[y][x]='X';
        draw();          //draw it
        i++;
    }
    printf("You lose\n");
}
