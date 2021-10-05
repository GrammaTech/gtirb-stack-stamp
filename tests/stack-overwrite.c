#include <stdio.h>

void B() asm("function_B");

void A(int flag) {
  printf("Function A\n");
  fflush(NULL);
  if (flag) {
    ((void**)__builtin_frame_address(0))[1] = &B;
  }
}

void B() {
  printf("Function B\n");
  fflush(NULL);
}

int main(int argc, char** argv) { A(argc > 1 ? 0 : 1); }
