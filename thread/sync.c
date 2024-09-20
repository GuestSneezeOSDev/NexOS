#include "sync.h"
#include "debug.h"
#include "interrupt.h"
#include "list.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "thread.h"

void sema_init(struct semaphore *psema, uint8_t _value) {
  psema->value = _value;
  list_init(&psema->waiters);
}

void lock_init(struct lock *plock) {
  plock->holder = NULL;
  plock->holder_repeat_nr = 0;
  sema_init(&plock->sema, 1);
}

void sema_down(struct semaphore *psema) {
  enum intr_status old_status = intr_disable();

  struct task_struct *cur_thread = running_thread();
  while (psema->value == 0) {
    if (list_elem_find(&psema->waiters, &cur_thread->general_tag)) {
      PANIC("The thread blocked has been in waiters list\n");
    }
    list_append(&psema->waiters, &cur_thread->general_tag);
    thread_block(TASK_BLOCKED);
  }

  psema->value--;
  ASSERT(psema->value == 0);

  intr_set_status(old_status);
}

void sema_up(struct semaphore *psema) {
  enum intr_status old_status = intr_disable();
  ASSERT(psema->value == 0);
  if (!list_empty(&psema->waiters)) {
    struct list_elem *blocked_thread_tag = list_pop(&psema->waiters);
    struct task_struct *blocked_thread =
        elem2entry(struct task_struct, general_tag, blocked_thread_tag);
    thread_unblock(blocked_thread);
  }
  psema->value++;
  ASSERT(psema->value == 1);
  intr_set_status(old_status);
}

void lock_acquire(struct lock *plock) {
  if (plock->holder != running_thread()) {
    sema_down(&plock->sema);
    plock->holder = running_thread();
    ASSERT(plock->holder_repeat_nr == 0);
    plock->holder_repeat_nr = 1;
  } else {
    plock->holder_repeat_nr++;
  }
}

void lock_release(struct lock *plock) {
  ASSERT(plock->holder == running_thread());
  if (plock->holder_repeat_nr > 1) {
    plock->holder_repeat_nr--;
    return;
  }
  ASSERT(plock->holder_repeat_nr == 1);

  plock->holder = NULL;
  plock->holder_repeat_nr = 0;
  sema_up(&plock->sema);
}
