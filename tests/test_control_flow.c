#include <stdio.h>

void func2(int remainder) {
  printf("in func2(%d)\n", remainder);
  if (remainder > 0) {
    func2(remainder - 1);
  }
  printf("exiting func2\n");
}

void func1() {
  printf("in func1\n");
  func2(5);
  printf("exiting func1\n");
}

int main() {
  printf("in main\n");
  func1();
  printf("exiting main\n");
  return 0;
}
