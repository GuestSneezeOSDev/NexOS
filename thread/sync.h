#ifndef __THREAD_SYNC_H
#define __THREAD_SYNC_H
#include "list.h"
#include "stdint.h"
#include "thread.h"

struct semaphore {
  uint8_t value;
  struct list waiters;
};

struct lock {
  struct task_struct *holder;
  struct semaphore sema;
  uint32_t holder_repeat_nr;
};

void lock_init(struct lock *plock);
void lock_acquire(struct lock *plock);
void lock_release(struct lock *plock);
void sema_init(struct semaphore *psema, uint8_t _value);
void sema_down(struct semaphore *psema);
void sema_up(struct semaphore *psema);
#endif
