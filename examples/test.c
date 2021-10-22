#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

struct Node {
  struct Node * next;
  int val;
};


// Globals
struct Node * head;
struct Node * curr;

int baz(int fd) {
  char buff[10];
  int size = read(fd, &buff, sizeof(buff));
  return buff[0] - '0';
}

int bar(char* path) {
  return open(path, O_RDONLY);
}

int foo(int num_nodes) {
  // Tracked file open
  int fd = bar("./test.txt");
  // Read taint
  int some_number = baz(fd);
  // libc function
  printf("%d\n", some_number);

  int i = 0;
  // Tainted loop invariant
  while (i < some_number) {
    struct Node * new_node = (struct Node*)malloc(sizeof(*new_node));
    // Tainted value in the heap
    new_node->val = some_number - i;

    // Global access
    if (i == 0) {
      head = new_node;
      curr = new_node;
    }
    else {
      curr->next = new_node;
      curr = new_node;
    }
    i += 1;
  }

  return some_number;
}


int main(int argc, char * argv[]) {
  // env var
  int ret_val = foo(argc);
  return ret_val;
}