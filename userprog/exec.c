#include "fs.h"
#include "global.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_kernel.h"
#include "string.h"
#include "thread.h"

#define EI_NIDENT (16)
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Addr;

extern void intr_exit();

struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT]; 
  Elf32_Half e_type;                
  Elf32_Half e_machine;             
  Elf32_Word e_version;             
  Elf32_Addr e_entry;               
  Elf32_Off e_phoff;                
  Elf32_Off e_shoff;                
  Elf32_Word e_flags;               
  Elf32_Half e_ehsize;              
  Elf32_Half e_phentsize;           
  Elf32_Half e_phnum;               
  Elf32_Half e_shentsize;          
  Elf32_Half e_shnum;               
  Elf32_Half e_shstrndx;            
};

struct Elf32_Phdr {
  Elf32_Word p_type;   
  Elf32_Off p_offset;  
  Elf32_Addr p_vaddr;  
  Elf32_Addr p_paddr;  
  Elf32_Word p_filesz; 
  Elf32_Word p_memsz;  
  Elf32_Word p_flags;  
  Elf32_Word p_align;  
};

enum segment_type {
  PT_NULL,    
  PT_LOAD,    
  PT_DYNAMIC, 
  PT_INTERP,  
  PT_NOTE,    
  PT_SHLIB,   
  PT_PHDR     
};

static bool segment_load(int32_t fd, uint32_t offset, uint32_t file_sz,
                         uint32_t vaddr) {

  uint32_t vaddr_first_page = vaddr & 0xfffff000;
  uint32_t size_in_first_page = PAGE_SIZE - (vaddr & 0x00000fff);

  uint32_t segment_page_count = 0;

  if (file_sz > size_in_first_page) {
    uint32_t left_size = file_sz - size_in_first_page;
    segment_page_count = DIV_ROUND_UP(left_size, PAGE_SIZE) + 1;
  } else {
    segment_page_count = 1;
  }
  uint32_t page_idx = 0;
  uint32_t vaddr_page = vaddr_first_page;
  while (page_idx < segment_page_count) {
    uint32_t *pde = pde_ptr(vaddr_page);
    uint32_t *pte = pte_ptr(vaddr_page);

    if (!(*pde & 0x00000001) || !(*pte & 0x00000001)) {
      if (get_a_page(PF_USER, vaddr_page) == NULL) {
        return false;
      }
    }
    vaddr_page += PAGE_SIZE;
    page_idx++;
  }
  sys_lseek(fd, offset, SEEK_SET);
  sys_read(fd, (void *)vaddr, file_sz);
  return true;
}

static int32_t load(const char *pathname) {
  struct Elf32_Ehdr elf_header;
  struct Elf32_Phdr prog_header;
  memset(&elf_header, 0, sizeof(struct Elf32_Ehdr));

  int32_t fd = sys_open(pathname, O_RDONLY);
  if (fd == -1) {
    return -1;
  }

  int32_t ret_val = -1;
  if (sys_read(fd, &elf_header, sizeof(struct Elf32_Ehdr)) !=
      sizeof(struct Elf32_Ehdr)) {
    ret_val = -1;
    goto done;
  }

  if (memcmp(elf_header.e_ident, "\177ELF\1\1\1", 7) ||
      elf_header.e_type != 2 || elf_header.e_machine != 3 ||
      elf_header.e_version != 1 || elf_header.e_phnum > 1024 ||
      elf_header.e_phentsize != sizeof(struct Elf32_Phdr)) {
    ret_val = -1;
    goto done;
  }

  Elf32_Off prog_header_offset = elf_header.e_phoff;
  Elf32_Half prog_header_entry_size = elf_header.e_phentsize;
  Elf32_Half prog_header_entry_count = elf_header.e_phnum;

  uint32_t prog_idx = 0;
  struct task_struct *cur = running_thread();
  while (prog_idx < prog_header_entry_count) {
    memset(&prog_header, 0, prog_header_entry_size);
    sys_lseek(fd, prog_header_offset, SEEK_SET);

    if (sys_read(fd, &prog_header, prog_header_entry_size) !=
        prog_header_entry_size) {
      ret_val = -1;
      goto done;
    }

    if (prog_header.p_type == PT_LOAD) {
      if (!segment_load(fd, prog_header.p_offset, prog_header.p_filesz,
                        prog_header.p_vaddr)) {
        ret_val = -1;
        goto done;
      }
      block_desc_init(cur->u_mb_desc_arr);
    }
    prog_header_offset += prog_header_entry_size;
    prog_idx++;
  }
  ret_val = elf_header.e_entry;
done:
  sys_close(fd);
  return ret_val;
}

int32_t sys_execv(const char *path, char *const argv[]) {
  int32_t argc = 0;
  while (argv[argc]) {
    argc++;
  }

  int32_t entry_point = load(path);
  if (entry_point == -1)
    return -1;

  struct task_struct *cur = running_thread();
  memcpy(cur->name, path, TASK_NAME_LEN);
  cur->name[TASK_NAME_LEN - 1] = 0;

  struct intr_stack *intr_stack_0 =
      (struct intr_stack *)((uint32_t)cur + PAGE_SIZE -
                            sizeof(struct intr_stack));
  intr_stack_0->ebx = (int32_t)argv;
  intr_stack_0->ecx = argc;
  intr_stack_0->eip = (void *)entry_point;
  intr_stack_0->esp = (void *)0xc0000000;

  asm volatile("movl %0, %%esp; jmp intr_exit" ::"g"(intr_stack_0) : "memory");

  return 0;
}
