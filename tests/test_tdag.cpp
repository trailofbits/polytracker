#include <cstdio>
#include <cstring>

int main(int argc, char *argv[]) {
  char outname[256];
  if (argc < 1) {
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    return 2;
  }

  char data[8];
  ::fread(data, sizeof(data), 1, f);

  // Range
  short r1 = data[0]*10+data[1];

  // Range 2
  int r2 = data[3]*100+data[2]*100+data[1]*10+data[0];

  // Union
  bool eq = data[0] == data[7];

  // All of r1 affects cf
  if (r1 == 0) {
    printf("r1 is zero\n");
  }

  // Union affects cf
  if (eq) {
    printf("first and last values are equal\n");
  }

  // Single value affects cf
  if (data[6] == 'c') {
    printf("seventh value is c\n");
  }

  // Yes, this is not safe. But we are only using it in our tests so it should be ok.
  strcpy(outname, argv[1]);
  strcat(outname, ".out");

  FILE *fout = fopen(outname, "wb");
  fwrite(&r2, sizeof(r2), 1, fout);
  fwrite(&eq, sizeof(eq), 1, fout);
  fwrite(&data[4], sizeof(data[4]), 1, fout); // Not affecting cf

  return 0;
}