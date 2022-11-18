#include <cstdio>

int main(int argc, char *argv[]) {
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    return 2;
  }

  fseek(f, 2, SEEK_CUR);

  char data[2];
  ::fread(data, sizeof(data), 1, f);

  return 0;
}