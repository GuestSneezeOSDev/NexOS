
#include "process.h"
#include "console.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "string.h"
#include "thread.h"
#include "tss.h"
#include "userprog.h"

extern void intr_exit(void);
extern struct list thread_ready_list;
extern struct list thread_all_list;

void start_process(void *_filename) {
  void *function = _filename;
  struct task_struct *cur_thread = running_thread();
  cur_thread->self_kstack += sizeof(struct thread_stack);
  struct intr_stack *proc_stack = (struct intr_stack *)cur_thread->self_kstack;

  proc_stack->edi = proc_stack->esi = 0;
  proc_stack->ebp = proc_stack->esp_dummy = 0;
  proc_stack->ebx = proc_stack->edx = 0;
  proc_stack->ecx = proc_stack->eax = 0;

  proc_stack->gs = 0;
  proc_stack->ds = proc_stack->es = proc_stack->fs = SELECTOR_U_DATA;

  proc_stack->cs = SELECTOR_U_CODE;
  proc_stack->eip = function;

  proc_stack->eflags = (EFLAGS_IF_1 | EFLAGS_IOPL_0 | EFLAGS_MBS);

  proc_stack->ss = SELECTOR_U_DATA;

  proc_stack->esp =
      (void *)((uint32_t)get_a_page(PF_USER, USER_STACK3_VADDR) + PAGE_SIZE);

  asm volatile("movl %0,%%esp; jmp intr_exit" ::"g"(proc_stack) : "memory");
}

void page_dir_activate(struct task_struct *pthread) {
  uint32_t page_dir_phy_addr = 0x100000;
  if (pthread->pg_dir != NULL) {
    page_dir_phy_addr = addr_v2p((uint32_t)pthread->pg_dir);
  }
  asm volatile("movl %0, %%cr3" ::"r"(page_dir_phy_addr) : "memory");
}


void process_activate(struct task_struct *pthread) {
  ASSERT(pthread != NULL);
  page_dir_activate(pthread);
  if (pthread->pg_dir) {
    update_tss_esp(pthread);
  }
}

uint32_t *create_page_dir(void) {
  uint32_t *user_page_dir_vaddr = get_kernel_pages(1);
  if (user_page_dir_vaddr == NULL) {
    console_put_str("create_page_dir: get_kernel_pages failed!");
    return NULL;
  }

 
  memcpy((uint32_t *)((uint32_t)user_page_dir_vaddr + 0x300 * 4),
         (uint32_t *)(0xfffff000 + 0x300 * 4), 1024);

  uint32_t user_page_dir_phy_addr = addr_v2p((uint32_t)user_page_dir_vaddr);
  user_page_dir_vaddr[1023] =
      user_page_dir_phy_addr | PG_US_U | PG_RW_W | PG_P_1;
  return user_page_dir_vaddr;
}

void create_user_vaddr_bitmap(struct task_struct *user_prog) {
  user_prog->userprog_vaddr.vaddr_start = USER_VADDR_START;

  uint32_t bitmap_pg_cnt =
      DIV_ROUND_UP((0xc0000000 - USER_VADDR_START) / PAGE_SIZE / 8, PAGE_SIZE);
  user_prog->userprog_vaddr.vaddr_bitmap.bits = get_kernel_pages(bitmap_pg_cnt);
  user_prog->userprog_vaddr.vaddr_bitmap.bmap_bytes_len =
      (0xc0000000 - USER_VADDR_START) / PAGE_SIZE / 8;
  bitmap_init(&user_prog->userprog_vaddr.vaddr_bitmap);
}


void process_execute(void *filename, char *name) {
  struct task_struct *user_thread = get_kernel_pages(1);
  ASSERT(user_thread != NULL);
  init_thread(user_thread, name, default_prio);
  create_user_vaddr_bitmap(user_thread);
  thread_create(user_thread, start_process, filename);
  user_thread->pg_dir = create_page_dir();

  block_desc_init(user_thread->u_mb_desc_arr);

  enum intr_status old_status = intr_disable();
  ASSERT(!list_elem_find(&thread_ready_list, &user_thread->general_tag));
  list_append(&thread_ready_list, &user_thread->general_tag);
  ASSERT(!list_elem_find(&thread_all_list, &user_thread->all_list_tag));
  list_append(&thread_all_list, &user_thread->all_list_tag);
  intr_set_status(old_status);
}
