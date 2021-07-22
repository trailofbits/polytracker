#include <setjmp.h>
#include <assert.h>
#include <stdio.h>

static jmp_buf gBuff;
int num_rec_calls = 0u;
__attribute__((weak)) int __polytracker_size() {
	fprintf(stderr, "WARNING USING WEAK SYMBOL\n");
	return -1;
}

int recursive() {
  if (num_rec_calls == 0) {
    int val = setjmp(gBuff);
    printf("Val is %d\n", val);
    if (val != 0) {
      int weak_val = __polytracker_size();
      printf("Returning weak val %d\n", weak_val);
      return weak_val;
    } else {
      num_rec_calls += 1;
      return recursive();
    }
  } else if (num_rec_calls < 10) {
    num_rec_calls += 1;
    return recursive();
  } else {
    longjmp(gBuff, 1);
  }
}
int main(void) {
  int size = __polytracker_size();
  int post_size = recursive();
  post_size = __polytracker_size();
  fprintf(stderr, "init size is %d\n", size);
  fprintf(stderr, "post size is %d\n", post_size);
  assert(post_size == size);
  if (post_size == size) {
    return 0;
  }
  return -1;
}
