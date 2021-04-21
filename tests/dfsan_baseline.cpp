#include <assert.h>
#include <iostream>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label("i", 0);
  dfsan_set_label(i_label, &i, sizeof(i));
  std::cout << "i label " << i_label << std::endl;

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j", 0);
  dfsan_set_label(j_label, &j, sizeof(j));
  std::cout << "j label " << j_label << std::endl;

  int k = 3;
  dfsan_label k_label = dfsan_create_label("k", 0);
  dfsan_set_label(k_label, &k, sizeof(k));
  std::cout << "k label " << k_label << std::endl;

  dfsan_label ij_label = dfsan_get_label(i + j);
  assert(dfsan_has_label(ij_label, i_label));
  assert(dfsan_has_label(ij_label, j_label));
  assert(!dfsan_has_label(ij_label, k_label));
  std::cout << "ij label " << ij_label << std::endl;

  dfsan_label ijk_label = dfsan_get_label(i + j + k);
  assert(dfsan_has_label(ijk_label, i_label));
  assert(dfsan_has_label(ijk_label, j_label));
  assert(dfsan_has_label(ijk_label, k_label));
  std::cout << "ijk label " << ijk_label << std::endl;

  if (k == j) {
    printf("Equal!\n");
  } else {
    printf("Not equal\n");
  }

  return 0;
}
