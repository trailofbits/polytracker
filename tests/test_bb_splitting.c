__attribute__((noinline)) void func2() {}
__attribute__((noinline)) void func3() {}
__attribute__((noinline)) void func4() {}
__attribute__((noinline)) void func5() {}

__attribute__((noinline)) void func1(volatile int *choice) {
  func2();
  if (*choice) {
    for (int i = 0; i < *choice; ++i) {
      func3();
    }
  } else {
    func4();
  }
  func5();
}

int main() {
  volatile int choice = 0;
  func1(&choice);
  choice = 2;
  func1(&choice);
  return 0;
}
