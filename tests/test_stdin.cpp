#include <cassert>
#include <cstdint>
#include <unistd.h>
#include <string>

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
// the following functions can be used
// read,
int main(int argc, char *argv[]) {
  assert(argc == 2);
  std::string_view method{argv[1]};

  if (method == "read") {
    return stdin_read();
  } else if (method == "fread") {
    return stdin_fread();
  } else if (method == "getc") {
    return stdin_getc();
  } else if (method == "getc_unlocked") {
    return stdin_getc_unlocked();
  } else if (method == "getchar") {
    return stdin_getchar();
  } else if (method == "getchar_unlocked") {
    return stdin_getchar_unlocked();
  } else if (method == "fgetc") {
    return stdin_fgetc();
  }
  return 0;
}