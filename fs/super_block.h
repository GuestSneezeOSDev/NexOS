#ifndef __FS_SUPER_BLOCK
#define __FS_SUPER_BLOCK

#include "stdint.h"

struct super_block {
  uint32_t magic;

  uint32_t sector_cnt;
  uint32_t inode_cnt;
  uint32_t partition_LBA_addr;

  uint32_t free_blocks_bitmap_LBA;
  uint32_t free_blocks_bitmap_sectors;

  uint32_t inode_bitmap_LBA;
  uint32_t inode_bitmap_sectors;

  uint32_t inode_table_LBA;
  uint32_t inode_table_sectors;

  uint32_t data_start_LBA;
  uint32_t root_inode_NO;
  uint32_t dir_entry_size;

  uint8_t pad[460];
} __attribute__((packed));

#endif
