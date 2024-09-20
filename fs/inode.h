#ifndef __FS_INODE_H
#define __FS_INODE_H
#include "global.h"
#include "ide.h"
#include "list.h"
#include "stdint.h"

struct inode {
  uint32_t i_NO;
  uint32_t i_size;
  uint32_t i_open_cnt;
  bool write_deny;

  uint32_t i_blocks[13];
  struct list_elem inode_tag;
};

void inode_close(struct inode *inode);
void inode_init(uint32_t inode_NO, struct inode *new_inode);
void inode_sync(struct partition *part, struct inode *inode, void *io_buf);
struct inode *inode_open(struct partition *part, uint32_t inode_NO);
void inode_release(struct partition *part, uint32_t inode_NO);
#endif
