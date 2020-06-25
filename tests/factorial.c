#include <stdio.h>
#include <stdlib.h>

unsigned long long factorial(unsigned long long n) {
  if (n == 0) {
    return 1;
  } else {
    return n * factorial(n - 1);
  }
}

int main(int argc, char** argv) {
  unsigned int n;
  if (argc != 2) {
    printf("USAGE: factorial [NUM]\n");
    return 1;
  } else {
    n = atoi(argv[1]);
    printf("Factorial(%u)=%llu\n", n, factorial(n));
    return 0;
  }
}
