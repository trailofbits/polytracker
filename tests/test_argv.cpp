#include <cstring>
#include <cstdio>

int main(int argc, char *argv[]) {
  auto f = fopen("outputfile.txt", "w");
  for (int i=0;i<argc;i++) {
    fwrite(argv[i], strlen(argv[i]), 1, f);
  }
  fclose(f);
}