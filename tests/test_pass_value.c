#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Test pass by value and tainting
// Both parameters should have taint labels

void cat_stuff(char first, char sec) {
  printf("This is a test, check first/sec taint labels, %c, %c\n", first, sec);
  if (first == sec) {
    printf("They are the same!\n");
  }
  printf("done!\n");
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Error, no file specified!");
  }
  FILE *fd = fopen(argv[1], "r");
  if (fd == NULL) {
    printf("Could not open file!\n");
  } else {
    char first;
    int bytes_read = fread(&first, 1, 1, fd);
    char next;
    bytes_read = fread(&next, 1, 1, fd);
    cat_stuff(first, next);
    fclose(fd);
  }
  return 0;
}
