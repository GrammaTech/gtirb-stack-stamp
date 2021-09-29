#include <stdio.h>

void B() asm("function_B");

void A() {
  printf("Function A\n");
  fflush(NULL);
  __asm__("lea function_B(%rip), %rax\n\t"
          "mov %rax, 8(%rbp)\n\t");
}

void B() {
  printf("Function B\n");
  fflush(NULL);
}

int main(int argc, char** argv) { A(); }
