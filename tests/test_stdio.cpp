#include <stdint.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc < 1) {
    return 1;
  }

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    return 2;
  }

  char arr[2];
  fread(&arr, sizeof(arr), 1, f);
  if (arr[0] == '{') {
    uint16_t val = (uint16_t)*arr;
    val += 1;
    fwrite(&val, sizeof(char), 1, stdout);
    fwrite(&val, sizeof(char), 1, stderr);
  }

  return 0;
}