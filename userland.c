#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  setreuid(4321, 1234);
  system("/bin/bash");

  return 0;
}
