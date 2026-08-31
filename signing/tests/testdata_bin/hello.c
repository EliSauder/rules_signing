// Test fixture: cross-compiled to a real Mach-O and a real PE binary so tool
// detection is verified against genuine executables rather than synthetic
// headers.
#include <stdio.h>

int main(void) {
  printf("hello from rules_signing\n");
  return 0;
}
