#include <stdio.h>

static int foo(int x) {
  return x + 1;
}

static int bar(int x) {
  return foo(x) * 2;
}

int main(void) {
  int v = 21;
  int r = bar(v);
  printf("r=%d\n", r);
  return 0;
}

