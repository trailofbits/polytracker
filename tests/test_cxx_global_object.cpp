#include <cassert>
#include <cstdio>

static struct GlobalObject {
  GlobalObject() : f(fopen("/proc/self/exe", "rb")) {
    assert(f);
    read_first();
  }

  void read_first() {
    auto n = fread(&v1, 1, 1, f);
    assert(n == 1);
  }

  ~GlobalObject() { fclose(f); }

  char v1;
  FILE* f;
} glob;

bool b(char tainted_value) { return tainted_value == 'L'; }

bool read_new_taint() {
  char c;
  auto n = fread(&c, 1, 1, glob.f);
  assert(n == 1);
  return c == 0;
}

int main(int argc, char *argv[]) {
  if (b(glob.v1))
    printf("b taint\n");

  if (read_new_taint())
    printf("New taint\n");
  return 0;
}