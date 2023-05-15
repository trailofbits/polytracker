#include <numeric>
#include <cstring>
#include <limits>
#include <iostream>
#include <unistd.h>

int32_t read_buffer_size() {
  int32_t length;
  if (read(0, &length, sizeof(length)) != sizeof(length)) {
    return -1;
  }

  if (length <= 0) {
    return -1;
  }
  return length;
}

int32_t read_buffer_of_size(int32_t length, char *dstbuffer, int32_t dstlen) {
  int32_t buffer_size = 100;
  // NOTE: Undefined behaviour here
  if (buffer_size + length < buffer_size) {
    std::cout << "Buffer overflow attempt detected! Fail. Length was " << length << std::endl;;
    return -1;
  } else {
    auto n = read(0, dstbuffer, length);
    return n;
  }
}

void print_summary(char *buffer, int32_t len) {
  auto sum = std::accumulate(buffer, buffer + len, 0);
  if (sum > 5) {
    std::cout << "More than five!" << std::endl;
  }
  std::cout << "Accumulated bytes are " << sum << std::endl;
}

int main(int argc, char* argv[]) {

  char buffer[100];
  int32_t incoming_buffer_size = read_buffer_size();
  int32_t nread = read_buffer_of_size(incoming_buffer_size, buffer, sizeof(buffer));
  std::cout << "nread: " << nread << std::endl;
  if (-1 == nread) {
    return -1;
  }
  print_summary(buffer, nread);

  return 0;
}