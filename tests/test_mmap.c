#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Tests that we can acquire the open taint source
 * and that mmap sets taint
 */

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Error, no file specified!\n");
    return -1;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    printf("Could not open file!\n");
  } else {
    struct stat filestat;
    if (fstat(fd, &filestat) != 0) {
      perror("stat failed");
      return -1;
    }
    char *data = mmap(NULL, filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
      perror("mmap failed");
      return -1;
    }
    if (data[0] == 'a') {
      printf("byte 0 is a!");
    }
    munmap(data, filestat.st_size);
    close(fd);
  }
  return 0;
}
