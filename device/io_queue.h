#ifndef __DEVICE_IOQUEUE_H
#define __DEVICE_IOQUEUE_H
#include "stdint.h"
#include "sync.h"
#include "thread.h"

#define BUF_SIZE 64

struct ioqueue {
  struct lock _lock;
  struct task_struct *producer;
  struct task_struct *consumer;
  char buf[BUF_SIZE];
  int32_t head;
  int32_t tail;
};

void ioqueue_init(struct ioqueue *ioq);
bool ioq_is_full(struct ioqueue *ioq);
bool ioq_is_empty(struct ioqueue *ioq);
char ioq_getchar(struct ioqueue *ioq);
void ioq_putchar(struct ioqueue *ioq, char ch);
#endif
