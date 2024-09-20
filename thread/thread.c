#include "thread.h"
#include <stdio.h>
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "print.h"
#include "process.h"
#include "stdint.h"
#include "string.h"
#include "switch.h"
#include "sync.h"

struct task_struct *main_thread;
struct task_struct *idle_thread;
struct list thread_ready_list;
struct list thread_all_list;
struct lock pid_lock;

extern void init();

struct task_struct *running_thread() {
  uint32_t esp;
  asm("mov %%esp,%0" : "=g"(esp));
  return (struct task_struct *)(esp & 0xfffff000);
}

static pid_t allocate_pid() {
  static pid_t next_pid = 0;
  lock_acquire(&pid_lock);
  next_pid++;
  lock_release(&pid_lock);
  return next_pid;
}

static void kernel_thread(thread_func *function, void *func_arg) {
  intr_enable();
  function(func_arg);
}

void thread_create(struct task_struct *thread, thread_func function,
                   void *func_arg) {
  thread->self_kstack -= sizeof(struct intr_stack);
  thread->self_kstack -= sizeof(struct thread_stack);

  struct thread_stack *kthread_stack =
      (struct thread_stack *)thread->self_kstack;

  kthread_stack->ebp = kthread_stack->ebx = 0;
  kthread_stack->esi = kthread_stack->edi = 0;

  kthread_stack->eip = kernel_thread;
  kthread_stack->function = function;
  kthread_stack->func_arg = func_arg;
}

void init_thread(struct task_struct *thread, char *name, int _priority) {
  memset(thread, 0, sizeof(*thread));
  thread->pid = allocate_pid();
  strcpy(thread->name, name);
  if (thread == main_thread) {
    thread->status = TASK_RUNNING;
  } else {
    thread->status = TASK_READY;
  }

  thread->self_kstack = (uint32_t *)((uint32_t)thread + PAGE_SIZE);
  thread->priority = _priority;
  thread->ticks = _priority;
  thread->elapsed_ticks = 0;
  thread->pg_dir = NULL;

  thread->fd_table[0] = 0;
  thread->fd_table[1] = 1;
  thread->fd_table[2] = 2;
  uint8_t fd_dix = 3;
  while (fd_dix < MAX_FILES_OPEN_PER_PROC) {
    thread->fd_table[fd_dix] = -1;
    fd_dix++;
  }

  thread->cwd_inode_NO = 0;
  thread->parent_pid = -1;
  thread->stack_magic = 0x20011124;
}

struct task_struct *thread_start(char *name, int _priority,
                                 thread_func function, void *func_arg) {
  struct task_struct *thread = get_kernel_pages(1);
  init_thread(thread, name, _priority);
  thread_create(thread, function, func_arg);

  ASSERT(!list_elem_find(&thread_ready_list, &thread->general_tag));
  list_append(&thread_ready_list, &thread->general_tag);
  ASSERT(!list_elem_find(&thread_all_list, &thread->all_list_tag));
  list_append(&thread_all_list, &thread->all_list_tag);

  return thread;
}

static void make_main_thread() {
  main_thread = running_thread();
  init_thread(main_thread, "main", 31);

  ASSERT(!list_elem_find(&thread_all_list, &main_thread->all_list_tag));
  list_append(&thread_all_list, &main_thread->all_list_tag);
}

void schedule() {
  ASSERT(intr_get_status() == INTR_OFF);
  struct task_struct *cur_thread = running_thread();
  if (cur_thread->status == TASK_RUNNING) {
    ASSERT(!list_elem_find(&thread_ready_list, &cur_thread->general_tag));

    list_append(&thread_ready_list, &cur_thread->general_tag);
    cur_thread->ticks = cur_thread->priority;
    cur_thread->status = TASK_READY;
  } else {
  }

  if (list_empty(&thread_ready_list)) {
    thread_unblock(idle_thread);
  }

  ASSERT(!list_empty(&thread_ready_list));
  struct list_elem *thread_tag;
  thread_tag = list_pop(&thread_ready_list);
  struct task_struct *next =
      elem2entry(struct task_struct, general_tag, thread_tag);
  next->status = TASK_RUNNING;
  process_activate(next);
  switch_to(cur_thread, next);
}

void thread_block(enum task_status stat) {
  ASSERT(stat == TASK_BLOCKED || stat == TASK_HANGING || stat == TASK_WAITING);
  enum intr_status old_status = intr_disable();
  struct task_struct *cur_thread = running_thread();
  cur_thread->status = stat;
  schedule();
  intr_set_status(old_status);
}

void thread_unblock(struct task_struct *pthread) {
  enum intr_status old_status = intr_disable();
  ASSERT(pthread->status == TASK_BLOCKED || pthread->status == TASK_HANGING ||
         pthread->status == TASK_WAITING);

  if (list_elem_find(&thread_ready_list, &pthread->general_tag))
    PANIC("blocked thread in ready_list\n");
  list_push(&thread_ready_list, &pthread->general_tag);
  pthread->status = TASK_READY;
  intr_set_status(old_status);
}

void thread_yield() {
  struct task_struct *cur_thread = running_thread();
  enum intr_status old_status = intr_disable();
  ASSERT(!list_elem_find(&thread_ready_list, &cur_thread->general_tag));
  list_append(&thread_ready_list, &cur_thread->general_tag);
  cur_thread->status = TASK_READY;
  schedule();
  intr_set_status(old_status);
}

static void idle(void *arg) {
  while (1) {
    thread_block(TASK_BLOCKED);

    asm volatile("sti; hlt" ::: "memory");
  }
}

pid_t fork_pid(void) { return allocate_pid(); }

static void print_in_format(char *buf, int32_t buf_len, void *ptr,
                            char format_flag) {
  memset(buf, 0, buf_len);
  uint8_t buf_idx = 0;
  switch (format_flag) {
    case 's':
      buf_idx = sprintf(buf, "%s", ptr);
      break;
    case 'd':
      buf_idx = sprintf(buf, "%d", *((int16_t *)ptr));
      break;
    case 'x':
      buf_idx = sprintf(buf, "%x", *((uint32_t *)ptr));
  }
  while (buf_idx < buf_len) {
    buf[buf_idx] = ' ';
    buf_idx++;
  }
  sys_write(STDOUT_NO, buf, buf_len - 1);
}

static bool print_task_info(struct list_elem *pelem, int arg UNUSED) {
  struct task_struct *pthread =
      elem2entry(struct task_struct, all_list_tag, pelem);
  char output_buf[16] = {0};

  print_in_format(output_buf, 16, &pthread->pid, 'd');
  if (pthread->parent_pid == -1) {
    print_in_format(output_buf, 16, "NULL", 's');
  } else {
    print_in_format(output_buf, 16, &pthread->parent_pid, 'd');
  }
  switch (pthread->status) {
    case 0:
      print_in_format(output_buf, 16, "RUNNING", 's');
      break;
    case 1:
      print_in_format(output_buf, 16, "READY", 's');
      break;
    case 2:
      print_in_format(output_buf, 16, "BLOCKED", 's');
      break;
    case 3:
      print_in_format(output_buf, 16, "WAITING", 's');
      break;
    case 4:
      print_in_format(output_buf, 16, "HANGING", 's');
      break;
    case 5:
      print_in_format(output_buf, 16, "DIED", 's');
  }
  print_in_format(output_buf, 16, &pthread->elapsed_ticks, 'x');

  memset(output_buf, 0, 16);
  ASSERT(strlen(pthread->name) <= 16);
  memcpy(output_buf, pthread->name, strlen(pthread->name));
  strcat(output_buf, "\n");
  sys_write(STDOUT_NO, output_buf, strlen(output_buf));
  return false;
}

void sys_ps() {
  char *ps_title =
      "PID            PPID           STAT           TICKS   "
      "     COMMAND\n";
  sys_write(STDOUT_NO, ps_title, strlen(ps_title));
  list_traversal(&thread_all_list, print_task_info, 0);
}

void thread_init() {
  put_str("thread_init start\n");
  list_init(&thread_ready_list);
  list_init(&thread_all_list);
  lock_init(&pid_lock);
  process_execute(init, "init");
  make_main_thread();
  idle_thread = thread_start("idle", 10, idle, NULL);
  put_str("thread_init done\n");
}
