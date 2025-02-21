#include <cstdint>
#include <unistd.h>
#include <cstring>
#include <iostream>

int stdin_read() {
  char inbyte;
  int sum = 0;

  while (true) {
    ssize_t ret = read(STDIN_FILENO, &inbyte, sizeof(inbyte));
    if (ret == sizeof(inbyte)) {
      sum += inbyte;
    } else if (ret == 0) {
      break;
    }
  }
  return sum;
}

int stdin_fread() {
  char inbyte;
  int sum = 0;

  while (!feof(stdin)) {
    size_t ret = fread(&inbyte, sizeof(inbyte), 1, stdin);
    if (ret == 1) {
      sum += inbyte;
    }
  }
  return sum;
}

int stdin_fgetc() {
  char inbyte;
  int sum = 0;

  while (true) {
    int ret = fgetc(stdin);
    if (ret == EOF)
      break;
    sum += inbyte;
  }
  return sum;
}

int stdin_getc() {
  char inbyte;
  int sum = 0;

  while (true) {
    int ret = getc(stdin);
    if (ret == EOF)
      break;
    sum += inbyte;
  }
  return sum;
}

int stdin_getc_unlocked() {
  char inbyte;
  int sum = 0;

  while (true) {
    int ret = getc_unlocked(stdin);
    if (ret == EOF)
      break;
    sum += inbyte;
  }
  return sum;
}

int stdin_getchar() {
  char inbyte;
  int sum = 0;

  while (true) {
    int ret = getchar();
    if (ret == EOF)
      break;
    sum += inbyte;
  }
  return sum;
}

int stdin_getchar_unlocked() {
  char inbyte;
  int sum = 0;

  while (true) {
    int ret = getchar_unlocked();
    if (ret == EOF)
      break;
    sum += inbyte;
  }
  return sum;
}

// Reads from stdin using different methods based on argv[1]
int main(int argc, char *argv[]) {
  if (argc != 2) {
    exit(EXIT_FAILURE);
  }
  
  if (std::strncmp(argv[1], "read", 4) == 0) {
    printf("got read\n");
    stdin_read();
  } else if (std::strncmp(argv[1], "fread", 5) == 0) {
    stdin_fread();
  } else if (std::strncmp(argv[1], "getc", 4) == 0) {
    stdin_getc();
  } else if (std::strncmp(argv[1], "getc_unlocked", 13) == 0) {
    stdin_getc_unlocked();
  } else if (std::strncmp(argv[1], "getchar", 7) == 0) {
    stdin_getchar();
  } else if (std::strncmp(argv[1], "getchar_unlocked", 16) == 0) {
    stdin_getchar_unlocked();
  } else if (std::strncmp(argv[1], "fgetc", 5) == 0) {
    stdin_fgetc();
  }

  exit(EXIT_SUCCESS);
}