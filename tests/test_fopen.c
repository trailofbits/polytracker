#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/*
 * Tests that we can acquire the fopen taint source
 * and that fread
 */

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Error, no file specified!");
  }
  FILE *fd = fopen(argv[1], "r");
  if (fd == NULL) {
    printf("Could not open file!\n");
  } else {
    char buff[2048];
    int bytes_read = fread(buff, 1, 1, fd);
    if (buff[0] == 'a') {
      printf("byte 0 is a!");
    }
    fclose(fd);
  }
  return 0;
}
