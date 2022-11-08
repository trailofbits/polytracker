#include <cstdint>
#include <unistd.h>
#include <string>

int main(int argc, char *argv[]) {
  int ret;
  char inbyte;
  int sum = 0;

  int skip_byte = argc > 1 ? std::stoi(argv[1]) : -1;

  for (int i=0;;) {
    ssize_t ret = ret = read(STDIN_FILENO, &inbyte, sizeof(inbyte));
    if (ret == sizeof(inbyte)) {
      if (i != skip_byte) {
        sum += inbyte;
      }
      i++;
    } else if (ret == 0) {
      break;
    }
    // Anything else, just try again
  }

  // Returning sum to ensure it is used and not optimized out
  return sum;
}