#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
void __dummy__(char x) {
 if (x == '\0') return;
 return;
}

int main(int argc, char ** argv) {
  FILE *fptr = fopen(argv[1], "r");
  if (fptr == NULL) {
    printf("Cannot open file \n");
    exit(1);
  }

  // Read contents from file
  char c = fgetc(fptr);
  while (c != EOF) {
    __dummy__(c);
    printf ("%c", c);
    c = fgetc(fptr);
  }

  fclose(fptr);
  return 0;
}
