#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// The idea of this testcase is that just moving things around
// Does not trigger taint, but looking back now I think it should.
int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Error, no file specified!");
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    printf("Could not open file!\n");
  } else {
    char buff[2048];
    memset(buff, 0, sizeof(buff));
    char other_buff[2048];
    memset(other_buff, 0, sizeof(other_buff));
    int bytes_read = read(fd, buff, 10);
    memcpy(other_buff, buff, sizeof(other_buff));
    close(fd);
  }
  return 0;
}
