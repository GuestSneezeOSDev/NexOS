#include "inode.h"
#include "bitmap.h"
#include "debug.h"
#include "file.h"
#include "ide.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"
#include "thread.h"

extern struct partition *cur_part;
struct inode_position {
  bool is_inode_cross_sectors;
  uint32_t sector_LBA;
  uint32_t offset_in_sector;
};

static void inode_locate(struct partition *part, uint32_t inode_NO,
                         struct inode_position *inode_pos) {
  ASSERT(inode_NO < 4096);
  uint32_t _inode_table_LBA = part->sup_b->inode_table_LBA;

  uint32_t inode_size = sizeof(struct inode);
  uint32_t offset_bytes = inode_NO * inode_size;
  uint32_t offset_sectors = offset_bytes / 512;
  uint32_t _offset_in_sector = offset_bytes % 512;

  if ((512 - _offset_in_sector) < inode_size) {
    inode_pos->is_inode_cross_sectors = true;
  } else {
    inode_pos->is_inode_cross_sectors = false;
  }

  inode_pos->sector_LBA = _inode_table_LBA + offset_sectors;
  inode_pos->offset_in_sector = _offset_in_sector;
}


void inode_sync(struct partition *part, struct inode *inode, void *io_buf) {
  uint32_t inode_NO = inode->i_NO;
  struct inode_position inode_pos;
  inode_locate(part, inode_NO, &inode_pos);
  ASSERT(inode_pos.sector_LBA <= (part->start_LBA + part->sector_cnt));

  struct inode pure_inode;
  memcpy(&pure_inode, inode, sizeof(struct inode));
  pure_inode.inode_tag.prev = pure_inode.inode_tag.next = NULL;
  pure_inode.i_open_cnt = 0;
  pure_inode.write_deny = false;

  char *inode_buf = (char *)io_buf;
  if (inode_pos.is_inode_cross_sectors) {
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 2);
    memcpy((inode_buf + inode_pos.offset_in_sector), &pure_inode,
           sizeof(struct inode));
    ide_write(part->which_disk, inode_pos.sector_LBA, inode_buf, 2);
  } else {
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 1);
    memcpy((inode_buf + inode_pos.offset_in_sector), &pure_inode,
           sizeof(struct inode));
    ide_write(part->which_disk, inode_pos.sector_LBA, inode_buf, 1);
  }
}

struct inode *inode_open(struct partition *part, uint32_t inode_NO) {
  struct list_elem *inode_iter = part->open_inodes.head.next;
  struct inode *inode_found;

  while (inode_iter != &part->open_inodes.tail) {
    inode_found = elem2entry(struct inode, inode_tag, inode_iter);
    if (inode_found->i_NO == inode_NO) {
      inode_found->i_open_cnt++;
      return inode_found;
    }
    inode_iter = inode_iter->next;
  }

  struct inode_position inode_pos;
  inode_locate(part, inode_NO, &inode_pos);

  struct task_struct *cur = running_thread();
  uint32_t *cur_pgdir_backup = cur->pg_dir;
  cur->pg_dir = NULL;
  inode_found = (struct inode *)sys_malloc(sizeof(struct inode));
  cur->pg_dir = cur_pgdir_backup;

  char *inode_buf;
  if (inode_pos.is_inode_cross_sectors) {
    inode_buf = (char *)sys_malloc(512 * 2);
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 2);
  } else {
    inode_buf = (char *)sys_malloc(512);
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 1);
  }
  memcpy(inode_found, inode_buf + inode_pos.offset_in_sector,
         sizeof(struct inode));

  list_push(&part->open_inodes, &inode_found->inode_tag);
  inode_found->i_open_cnt = 1;
  sys_free(inode_buf);
  return inode_found;
}

void inode_close(struct inode *inode) {
  enum intr_status old_status = intr_disable();
  if (--inode->i_open_cnt == 0) {
    list_remove(&inode->inode_tag);
    struct task_struct *cur = running_thread();
    uint32_t *cur_pgdir_backup = cur->pg_dir;
    cur->pg_dir = NULL;
    sys_free(inode);
    cur->pg_dir = cur_pgdir_backup;
  }
  intr_set_status(old_status);
}

void inode_init(uint32_t inode_NO, struct inode *new_inode) {
  new_inode->i_NO = inode_NO;
  new_inode->i_open_cnt = 0;
  new_inode->i_size = 0;
  new_inode->write_deny = false;

  uint8_t sector_idx = 0;
  while (sector_idx < 13) {
    new_inode->i_blocks[sector_idx] = 0;
    sector_idx++;
  }
}

void inode_delete(struct partition *part, uint32_t inode_NO, void *io_buf) {
  ASSERT(inode_NO < 4096);
  struct inode_position inode_pos;
  inode_locate(part, inode_NO, &inode_pos);
  ASSERT(inode_pos.sector_LBA <= (part->start_LBA + part->sector_cnt));

  char *inode_buf = (char *)io_buf;
  if (inode_pos.is_inode_cross_sectors) {
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 2);
    memset((inode_buf + inode_pos.offset_in_sector), 0, sizeof(struct inode));
    ide_write(part->which_disk, inode_pos.sector_LBA, inode_buf, 2);
  } else {
    ide_read(part->which_disk, inode_pos.sector_LBA, inode_buf, 1);
    memset((inode_buf + inode_pos.offset_in_sector), 0, sizeof(struct inode));
    ide_write(part->which_disk, inode_pos.sector_LBA, inode_buf, 1);
  }
}

void inode_release(struct partition *part, uint32_t inode_NO) {
  struct inode *inode_to_del = inode_open(part, inode_NO);
  ASSERT(inode_to_del->i_NO == inode_NO);

  uint8_t block_idx = 0;

  uint8_t block_cnt = 12;

  uint32_t block_bitmap_idx;

  uint32_t all_blocks_addr[140] = {0};

  while (block_idx < 12) {
    all_blocks_addr[block_idx] = inode_to_del->i_blocks[block_idx];
    block_idx++;
  }

  if (inode_to_del->i_blocks[12] != 0) {
    ide_read(part->which_disk, inode_to_del->i_blocks[12], all_blocks_addr + 12,
             1);
    block_cnt += 128;

    block_bitmap_idx = inode_to_del->i_blocks[12] - part->sup_b->data_start_LBA;
    ASSERT(block_bitmap_idx > 0);
    bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
  }

  block_idx = 0;
  while (block_idx < block_cnt) {
    if (all_blocks_addr[block_idx] != 0) {
      block_bitmap_idx = 0;
      block_bitmap_idx =
          all_blocks_addr[block_idx] - part->sup_b->data_start_LBA;
      ASSERT(block_bitmap_idx > 0);
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
    }
    block_idx++;
  }
  bitmap_set(&part->inode_bitmap, inode_NO, 0);
  bitmap_sync(cur_part, inode_NO, INODE_BITMAP);

  void *io_buf = sys_malloc(1024);
  inode_delete(part, inode_NO, io_buf);
  sys_free(io_buf);
  inode_close(inode_to_del);
}
