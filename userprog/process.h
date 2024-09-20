#ifndef __USERPROG_PROCESS_H
#define __USERPROG_PROCESS_H

#include "thread.h"
#define USER_VADDR_START 0x8048000
#define default_prio 31

void process_execute(void *filename, char *name);
void process_activate(struct task_struct *pthread);
void page_dir_activate(struct task_struct *pthread);
uint32_t *create_page_dir(void);
#endif
