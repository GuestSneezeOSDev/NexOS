#include "io_queue.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "stdio_kernel.h"
#include "sync.h"
#include "thread.h"

void ioqueue_init(struct ioqueue *ioq) {
  lock_init(&ioq->_lock);
  ioq->consumer = ioq->producer = NULL;
  ioq->head = ioq->tail = 0;
}

static int32_t next_pos(int32_t pos) { return (pos + 1) % BUF_SIZE; }

bool ioq_is_full(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  return next_pos(ioq->head) == ioq->tail;
}

bool ioq_is_empty(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  return ioq->tail == ioq->head;
}

static void ioq_wait(struct task_struct **waiter) {
  ASSERT(waiter != NULL && *waiter == NULL);
  *waiter = running_thread();
  thread_block(TASK_BLOCKED);
}

static void ioq_wakeup(struct task_struct **waiter) {
  ASSERT(*waiter != NULL);
  thread_unblock(*waiter);
  *waiter = NULL;
}

char ioq_getchar(struct ioqueue *ioq) {
  ASSERT(intr_get_status() == INTR_OFF);
  while (ioq_is_empty(ioq)) {
    lock_acquire(&ioq->_lock);
    ioq_wait(&ioq->consumer);
    lock_release(&ioq->_lock);
  }

  char ret_char = ioq->buf[ioq->tail];
  ioq->tail = next_pos(ioq->tail);

  if (ioq->producer != NULL)
    ioq_wakeup(&ioq->producer);

  return ret_char;
}

void ioq_putchar(struct ioqueue *ioq, char ch) {
  ASSERT(intr_get_status() == INTR_OFF);
  while (ioq_is_full(ioq)) {
    lock_acquire(&ioq->_lock);
    ioq_wait(&ioq->consumer);
    lock_release(&ioq->_lock);
  }
  ioq->buf[ioq->head] = ch;
  ioq->head = next_pos(ioq->head);

  if (ioq->consumer != NULL)
    ioq_wakeup(&ioq->consumer);
}
