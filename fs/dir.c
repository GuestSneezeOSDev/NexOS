#include "dir.h"
#include "bitmap.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"

struct dir root_dir;
extern struct partition *cur_part;

void open_root_dir(struct partition *part) {
  root_dir._inode = inode_open(part, part->sup_b->root_inode_NO);
  root_dir.dir_pos = 0;
}

struct dir *dir_open(struct partition *part, uint32_t inode_NO) {
  struct dir *pdir = (struct dir *)sys_malloc(sizeof(struct dir));
  pdir->_inode = inode_open(part, inode_NO);
  pdir->dir_pos = 0;
  return pdir;
}

bool search_dir_entry(struct partition *part, struct dir *pdir,
                      const char *name, struct dir_entry *dir_e) {

  uint32_t inode_blocks_cnt = 12 + (512 / 4);

  uint32_t *all_inode_blocks = (uint32_t *)sys_malloc(inode_blocks_cnt * 4);
  if (all_inode_blocks == NULL) {
    printk("search_dir_entry: sys_malloc for all_inode_blocks failed");
    return false;
  }

  uint32_t block_idx = 0;
  while (block_idx < 12) {
    all_inode_blocks[block_idx] = pdir->_inode->i_blocks[block_idx];
    block_idx++;
  }
  if (pdir->_inode->i_blocks[12] != 0) {
    ide_read(part->which_disk, pdir->_inode->i_blocks[12],
             all_inode_blocks + 12, 1);
  }

  uint8_t *buf = (uint8_t *)sys_malloc(BLOCK_SIZE);
  struct dir_entry *de_iter = (struct dir_entry *)buf;
  uint32_t _dir_entry_size = part->sup_b->dir_entry_size;
  uint32_t dir_entry_cnt = BLOCK_SIZE / _dir_entry_size;
  block_idx = 0;

  while (block_idx < inode_blocks_cnt) {
    if (all_inode_blocks[block_idx] == 0) {
      block_idx++;
      continue;
    }

    ide_read(part->which_disk, all_inode_blocks[block_idx], buf, 1);

    uint32_t dir_entry_idx = 0;
    while (dir_entry_idx < dir_entry_cnt) {
      if (!strcmp(de_iter->filename, name)) {
        memcpy(dir_e, de_iter, _dir_entry_size);
        sys_free(buf);
        sys_free(all_inode_blocks);
        return true;
      }
      dir_entry_idx++;
      de_iter++;
    }
    block_idx++;
    de_iter = (struct dir_entry *)buf;
    memset(buf, 0, BLOCK_SIZE);
  }
  sys_free(buf);
  sys_free(all_inode_blocks);
  return false;
}

void dir_close(struct dir *dir) {
  if (dir == &root_dir)
    return;
  inode_close(dir->_inode);
  sys_free(dir);
}

void create_dir_entry(char *filename, uint32_t inode_NO, uint8_t file_type,
                      struct dir_entry *p_de) {
  ASSERT(strlen(filename) < MAX_FILE_NAME_LEN);
  memcpy(p_de->filename, filename, strlen(filename));
  p_de->i_NO = inode_NO;
  p_de->f_type = file_type;
}

bool sync_dir_entry(struct dir *parent_dir, struct dir_entry *de,
                    void *io_buf) {
  struct inode *dir_inode = parent_dir->_inode;
  uint32_t dir_size = dir_inode->i_size;
  uint32_t _dir_entry_size = cur_part->sup_b->dir_entry_size;
  ASSERT(dir_size % _dir_entry_size == 0);

  uint32_t max_dir_entries_per_sector = SECTOR_SIZE / _dir_entry_size;
  int32_t block_LBA = -1;

  uint8_t block_idx = 0;
  uint32_t all_blocks[140] = {0};
  while (block_idx < 12) {
    all_blocks[block_idx] = dir_inode->i_blocks[block_idx];
    block_idx++;
  }

  int32_t block_bitmap_idx = -1;

  block_idx = 0;
  while (block_idx < 140) {
    block_bitmap_idx = -1;
    if (all_blocks[block_idx] == 0) {
      block_LBA = block_bitmap_alloc(cur_part);
      if (block_LBA == -1) {
        printk("allocate block bitmap for sync_dir_entry failed\n");
        return false;
      }

      block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
      ASSERT(block_bitmap_idx != -1);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);

      block_bitmap_idx = -1;
      if (block_idx < 12) {
        dir_inode->i_blocks[block_idx] = all_blocks[block_idx] = block_LBA;
      } else if (block_idx == 12) {
        dir_inode->i_blocks[12] = block_LBA;
        block_LBA = -1;
        block_LBA = block_bitmap_alloc(cur_part);
        if (block_LBA == -1) {
          block_bitmap_idx =
              dir_inode->i_blocks[12] - cur_part->sup_b->data_start_LBA;
          bitmap_set(&cur_part->block_bitmap, block_bitmap_idx, 0);
          dir_inode->i_blocks[12] = 0;
          printk("allocate block bitmap for sync_dir_entry failed");
          return false;
        }
        block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
        ASSERT(block_bitmap_idx != -1);
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        all_blocks[12] = block_LBA;
        ide_write(cur_part->which_disk, dir_inode->i_blocks[12],
                  all_blocks + 12, 1);
      } else {
                all_blocks[block_idx] = block_LBA;
        ide_write(cur_part->which_disk, dir_inode->i_blocks[12],
                  all_blocks + 12, 1);
      }
      memset(io_buf, 0, 512);
      memcpy(io_buf, de, _dir_entry_size);
      ide_write(cur_part->which_disk, block_LBA, io_buf, 1);

      dir_inode->i_size += _dir_entry_size;
      return true;
    } else {
      ide_read(cur_part->which_disk, all_blocks[block_idx], io_buf, 1);
      struct dir_entry *dir_entry_base = (struct dir_entry *)io_buf;
      uint8_t dir_entry_idx = 0;
      while (dir_entry_idx < max_dir_entries_per_sector) {
        if ((dir_entry_base + dir_entry_idx)->f_type == FT_UNKNOWN) {
          memcpy(dir_entry_base + dir_entry_idx, de, _dir_entry_size);
          ide_write(cur_part->which_disk, all_blocks[block_idx], io_buf, 1);
          dir_inode->i_size += _dir_entry_size;
          return true;
        }
        dir_entry_idx++;
      }
      block_idx++;
    }
  }
  printk("directory is full!\n");
  return false;
}

bool delete_dir_entry(struct partition *part, struct dir *pdir,
                      uint32_t inode_NO, void *io_buf) {
  struct inode *dir_inode = pdir->_inode;

  uint32_t block_idx = 0;
  uint32_t all_blocks_addr[140] = {0};
  while (block_idx < 12) {
    all_blocks_addr[block_idx] = dir_inode->i_blocks[block_idx];
    block_idx++;
  }
  if (dir_inode->i_blocks[12] != 0) {
    ide_read(part->which_disk, dir_inode->i_blocks[12], all_blocks_addr + 12,
             1);
  }

  uint32_t _dir_entry_size = part->sup_b->dir_entry_size;
  uint32_t max_dir_entries_per_sector = SECTOR_SIZE / _dir_entry_size;
  struct dir_entry *dir_entry_base = (struct dir_entry *)io_buf;
  struct dir_entry *dir_entry_found = NULL;
  uint8_t dir_entry_idx, dir_entry_cnt;
  bool is_dir_first_block = false;

  block_idx = 0;
  while (block_idx < 140) {
    is_dir_first_block = false;
    if (all_blocks_addr[block_idx] == 0) {
      block_idx++;
      continue;
    }
    dir_entry_idx = dir_entry_cnt = 0;
    memset(io_buf, 0, SECTOR_SIZE);
    ide_read(part->which_disk, all_blocks_addr[block_idx], io_buf, 1);

    while (dir_entry_idx < max_dir_entries_per_sector) {
      if ((dir_entry_base + dir_entry_idx)->f_type != FT_UNKNOWN) {
        if (!strcmp((dir_entry_base + dir_entry_idx)->filename, ".")) {
          is_dir_first_block = true;
        } else if (strcmp((dir_entry_base + dir_entry_idx)->filename, ".") &&
                   strcmp((dir_entry_base + dir_entry_idx)->filename, "..")) {
          dir_entry_cnt++;
          if ((dir_entry_base + dir_entry_idx)->i_NO == inode_NO) {
            ASSERT(dir_entry_found == NULL);
            dir_entry_found = dir_entry_base + dir_entry_idx;
          }
        }
      }
      dir_entry_idx++;
    }
    if (dir_entry_found == NULL) {
      block_idx++;
      continue;
    }
    ASSERT(dir_entry_cnt >= 1);
    if (dir_entry_cnt == 1 && !is_dir_first_block) {
      uint32_t block_bitmap_idx =
          all_blocks_addr[block_idx] - part->sup_b->data_start_LBA;
      bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
      bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);

      if (block_idx < 12) {
        dir_inode->i_blocks[block_idx] = 0;
      } else {
        uint32_t indirect_blocks_cnt = 0;
        uint32_t indirect_block_idx = 12;
        while (indirect_block_idx < 140) {
          if (all_blocks_addr[indirect_block_idx] != 0) {
            indirect_blocks_cnt++;
          }
        }
        ASSERT(indirect_blocks_cnt >= 1);
        if (indirect_blocks_cnt > 1) {
          all_blocks_addr[block_idx] = 0;
          ide_write(part->which_disk, dir_inode->i_blocks[12],
                    all_blocks_addr + 12, 1);
        } else {
          block_bitmap_idx =
              dir_inode->i_blocks[12] - part->sup_b->data_start_LBA;
          bitmap_set(&part->block_bitmap, block_bitmap_idx, 0);
          bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
          dir_inode->i_blocks[12] = 0;
        }
      }
    } else {
      memset(dir_entry_found, 0, _dir_entry_size);
      ide_write(part->which_disk, all_blocks_addr[block_idx], io_buf, 1);
    }
    ASSERT(dir_inode->i_size >= _dir_entry_size);
    dir_inode->i_size -= _dir_entry_size;
    memset(io_buf, 0, SECTOR_SIZE * 2);
    inode_sync(part, dir_inode, io_buf);
    return true;
  }
  return false;
}

struct dir_entry *dir_read(struct dir *dir) {
  struct dir_entry *dir_entry_buf = (struct dir_entry *)dir->dir_buf;
  struct inode *dir_inode = dir->_inode;
  uint32_t all_blocks_addr[140] = {0};
  uint32_t block_cnt = 12;
  uint32_t block_idx = 0;

  if (block_idx < 12) {
    all_blocks_addr[block_idx] = dir_inode->i_blocks[block_idx];
    block_idx++;
  }

  if (dir_inode->i_blocks[12] != 0) {
    ide_read(cur_part->which_disk, dir_inode->i_blocks[12],
             all_blocks_addr + 12, 1);
    block_cnt += 128;
  }
  block_idx = 0;

  uint32_t cur_dir_entry_pos = 0;
  uint32_t _dir_entry_size = cur_part->sup_b->dir_entry_size;
  uint32_t dir_entry_per_sector = SECTOR_SIZE / _dir_entry_size;
  uint32_t dir_entry_idx = 0;

  while (dir->dir_pos < dir_inode->i_size) {
    if (all_blocks_addr[block_idx] == 0) {
      block_idx++;
      continue;
    }

    memset(dir_entry_buf, 0, SECTOR_SIZE);
    ide_read(cur_part->which_disk, all_blocks_addr[block_idx], dir_entry_buf,
             1);
    dir_entry_idx = 0;
    while (dir_entry_idx < dir_entry_per_sector) {
      if ((dir_entry_buf + dir_entry_idx)->f_type != FT_UNKNOWN) {
        if (cur_dir_entry_pos < dir->dir_pos) {
          cur_dir_entry_pos += _dir_entry_size;
          dir_entry_idx++;
          continue;
        }
        ASSERT(cur_dir_entry_pos == dir->dir_pos);
        dir->dir_pos += _dir_entry_size;
        return dir_entry_buf + dir_entry_idx;
      }
      dir_entry_idx++;
    }
    block_idx++;
  }
  return NULL;
}

bool dir_is_empty(struct dir *dir) {
  struct inode *dir_inode = dir->_inode;
  return (dir_inode->i_size == (cur_part->sup_b->dir_entry_size * 2));
}

int32_t dir_remove(struct dir *parent_dir, struct dir *child_dir) {
  struct inode *child_dir_inode = child_dir->_inode;
  int32_t block_idx = 1;
  while (block_idx < 13) {
    ASSERT(child_dir_inode->i_blocks[block_idx] == 0);
    block_idx++;
  }

  void *io_buf = sys_malloc(SECTOR_SIZE * 2);
  if (io_buf == NULL) {
    printk("dir_is_empty: sys_malloc for io_buf failed\n");
    return -1;
  }

  delete_dir_entry(cur_part, parent_dir, child_dir_inode->i_NO, io_buf);
  inode_release(cur_part, child_dir_inode->i_NO);
  sys_free(io_buf);
  return 0;
}
