#ifndef __DEVICE_IDE_H
#define __DEVICE_IDE_H
#include "bitmap.h"
#include "list.h"
#include "stdint.h"
#include "sync.h"

struct partition {
  uint32_t start_LBA;
  uint32_t sector_cnt;
  struct disk *which_disk;
  struct list_elem part_tag;
  char name[8];
  struct super_block *sup_b;
  struct bitmap block_bitmap;
  struct bitmap inode_bitmap;
  struct list open_inodes;
};

struct disk {
  char name[8];
  struct ide_channel *which_channel;
  uint8_t dev_NO;
  struct partition prim_parts[4];
  struct partition logic_parts[8];
};

struct ide_channel {
  char name[8];
  int16_t port_base;
  uint8_t IRQ_NO;
  struct lock _lock;
  bool expecting_intr;
  struct semaphore disk_done;
  struct disk devices[2];
};

void ide_init();
void ide_write(struct disk *hd, uint32_t LBA, void *buf, uint32_t sector_cnt);
void ide_read(struct disk *hd, uint32_t LBA, void *buf, uint32_t sector_cnt);
#endif
