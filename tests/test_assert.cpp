#include <cassert>
#include <unistd.h>

int main(int argc, char *argv[]) {

  char data[2];
  read(0, data, sizeof(data));

  // This will terminate the program unexpectedly (tdag sizes might not be updated).
  assert(data[0] == data[1]);

}