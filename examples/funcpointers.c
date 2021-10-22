#include <stdio.h>

typedef FILE*	(*fopenfunc)(const char * __restrict __filename, const char * __restrict __mode) ;

int main(int argc, char*argv[]) {
fopenfunc fp = fopen;

FILE* f = fp(argv[0], "rb");
fseek(f, 0, SEEK_END);
printf("%s size is: %ld\n", argv[0], ftell(f));

fclose(f);
return 0;
}