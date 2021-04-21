#include <assert.h>
#include <iostream>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <vector>

void foo(dfsan_label test, dfsan_label test2) {
  if (test == test2) {
    std::cout << "Equal" << std::endl;
  } else {
    std::cout << "not equal" << std::endl;
  }
}

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label("i", 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j", 0);
  dfsan_set_label(j_label, &j, sizeof(j));

  int k = 3;
  dfsan_label k_label = dfsan_create_label("k", 0);
  dfsan_set_label(k_label, &k, sizeof(k));

  dfsan_label ij_label = dfsan_get_label(i + j);
  printf("%d\n", ij_label);
  if (k == j) {
    printf("Equal!\n");
  } else {
    printf("Not equal\n");
  }

  std::vector<dfsan_label> testme;
  testme.push_back(i);
  std::cout << testme[0] << std::endl;
  if (testme[0] == 3) {
    std::cout << "Its three!" << std::endl;
  }
  dfsan_label test_label = dfsan_get_label(testme[0]);
  std::cout << "test_label: " << test_label << std::endl;
  foo(k_label, testme[0]);
  return 0;
}
