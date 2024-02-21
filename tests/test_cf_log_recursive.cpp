#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

int f2(uint8_t val) {
  if (val & 1) {
    int r = val * val;
    if (r > 4) {
      val--;
      return f2(val);
    } else {
      return val + 1;
    }
  } else {
    return val + 2;
  }
}

int f1(uint8_t val) {
  bool a = true;
  while (a) {
    if (val % 2 == 0) {
      a &= false;
      return f2(val++);
    } else {
      val--;
      f1(val);
    }
  }
  return val;
}

// Some dummy control flow to test that control flow logging works as expected
int main(int argc, char *argv[]) {
  uint8_t buffer[sizeof(uint64_t)];
  if (sizeof(buffer) != read(0, buffer, sizeof(buffer))) {
    exit(EXIT_FAILURE);
  }

  int v = f1(7) + f1((int)buffer[3]);
  printf("You only live once, except recursively! v was %d\n", v);

  exit(EXIT_SUCCESS);
}