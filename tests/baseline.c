#include <assert.h>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>

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

  return 0;
}
