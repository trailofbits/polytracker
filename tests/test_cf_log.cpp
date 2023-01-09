#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

// Some dummy control flow to test that control flow logging works as expected
int main(int argc, char *argv[]) {
  uint8_t buffer[sizeof(uint64_t)];
  if (sizeof(buffer) != read(0, buffer, sizeof(buffer))) {
    exit(EXIT_FAILURE);
  }

  bool good = true;

  // Control flow 1, affects label 1
  if (buffer[0] == 'a') {
    // Control flow 2, affects label 2
    if (buffer[1] != 'c') {
      // Control flow labels 3 trough 8
      for (size_t i=2;i<sizeof(buffer);i++) {
        if (buffer[i] == '\0') {
          good = false;
        }
      }
    }
  }

  if (good) {
    // Union/range
    uint64_t val = 0;
    for (auto v : buffer) {
      val = (val << 8) | v;
    }
    // Control flow label 15. The range node covering the full input buffer
    if (val == 1) {
      printf("Wow, that was unexpected\n");
    }

    // Control flow label 3 (again)
    if (buffer[2] < 16) {
      printf("OK, buffer[2] < 16\n");
    }
  }
  exit(EXIT_SUCCESS);
}