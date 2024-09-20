#include "file.h"
#include "bitmap.h"
#include "debug.h"
#include "dir.h"
#include "fs.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "interrupt.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"
#include "syscall_init.h"
#include "thread.h"

struct file file_table[MAX_FILES_OPEN];
extern struct partition *cur_part;

int32_t get_free_slot_in_global_FT() {
  uint32_t fd_idx = 3;
  while (fd_idx < MAX_FILES_OPEN) {
    if (file_table[fd_idx].fd_inode == NULL)
      break;
    fd_idx++;
  }
  if (fd_idx == MAX_FILES_OPEN) {
    printk("exceed max open files\n");
    return -1;
  }
  return fd_idx;
}

int32_t pcb_fd_install(int32_t global_fd_idx) {
  struct task_struct *cur = running_thread();
  uint8_t local_fd_idx = 3;
  while (local_fd_idx < MAX_FILES_OPEN) {
    if (cur->fd_table[local_fd_idx] == -1) {
      cur->fd_table[local_fd_idx] = global_fd_idx;
      break;
    }
    local_fd_idx++;
  }
  if (local_fd_idx == MAX_FILES_OPEN_PER_PROC) {
    printk("exceed max open files for each process\n");
    return -1;
  }
  return local_fd_idx;
}
int32_t inode_bitmap_alloc(struct partition *part) {
  int32_t bit_idx = bitmap_scan(&part->inode_bitmap, 1);
  if (bit_idx == -1)
    return -1;
  bitmap_set(&part->inode_bitmap, bit_idx, 1);
  return bit_idx;
}

int32_t block_bitmap_alloc(struct partition *part) {
  int32_t bit_idx = bitmap_scan(&part->block_bitmap, 1);
  if (bit_idx == -1) {
    return -1;
  }
  bitmap_set(&part->block_bitmap, bit_idx, 1);
  return (part->sup_b->data_start_LBA + bit_idx);
}

void bitmap_sync(struct partition *part, uint32_t bit_idx, uint8_t btmp_flag) {
  uint32_t bit_offset_in_sector = bit_idx / (512 * 8);
  uint32_t bit_offset_in_byte = bit_offset_in_sector * BLOCK_SIZE;

  uint32_t sector_LBA;
  uint8_t *bitmap_offset;

  switch (btmp_flag) {
  case INODE_BITMAP:
    sector_LBA = part->sup_b->inode_bitmap_LBA + bit_offset_in_sector;
    bitmap_offset = part->inode_bitmap.bits + bit_offset_in_byte;
    break;
  case BLOCK_BITMAP:
    sector_LBA = part->sup_b->free_blocks_bitmap_LBA + bit_offset_in_sector;
    bitmap_offset = part->block_bitmap.bits + bit_offset_in_byte;
    break;
  }
  ide_write(part->which_disk, sector_LBA, bitmap_offset, 1);
}


int32_t file_create(struct dir *parent_dir, char *filename, uint8_t flag) {
  void *io_buf = sys_malloc(1024);
  if (io_buf == NULL) {
    printk("file_create: sys_malloc for io_buf failed\n");
    return -1;
  }

  uint8_t rollback_action = 0;

  int32_t new_inode_NO = inode_bitmap_alloc(cur_part);
  if (new_inode_NO == -1) {
    printk("file_create: allocate inode bit failed\n");
    return -1;
  }
  struct inode *new_inode = (struct inode *)sys_malloc(sizeof(struct inode));
  if (new_inode == NULL) {
    printk("file_create: sys_malloc for inode failed\n");
    rollback_action = 3;
    goto rollback;
  }
  inode_init(new_inode_NO, new_inode);

  int fd_idx = get_free_slot_in_global_FT();
  if (fd_idx == -1) {
    printk("exceed max open files\n");
    rollback_action = 2;
    goto rollback;
  }
  file_table[fd_idx].fd_flag = flag;
  file_table[fd_idx].fd_inode = new_inode;
  file_table[fd_idx].fd_pos = 0;
  file_table[fd_idx].fd_inode->write_deny = false;

  struct dir_entry new_dir_entry;
  memset(&new_dir_entry, 0, sizeof(struct dir_entry));
  create_dir_entry(filename, new_inode_NO, FT_REGULAR, &new_dir_entry);

  if (!sync_dir_entry(parent_dir, &new_dir_entry, io_buf)) {
    printk("sync dir_entry to disk failed\n");
    rollback_action = 1;
    goto rollback;
  }
  memset(io_buf, 0, 1024);
  inode_sync(cur_part, parent_dir->_inode, io_buf);
  memset(io_buf, 0, 1024);
  inode_sync(cur_part, new_inode, io_buf);
  bitmap_sync(cur_part, new_inode_NO, INODE_BITMAP);

  list_push(&cur_part->open_inodes, &new_inode->inode_tag);
  new_inode->i_open_cnt = 1;

  sys_free(io_buf);
  return pcb_fd_install(fd_idx);

rollback:
  switch (rollback_action) {
  case 1:
    memset(&file_table[fd_idx], 0, sizeof(struct file));
  case 2:
    sys_free(new_inode);
  case 3:
    bitmap_set(&cur_part->inode_bitmap, new_inode_NO, 1);
    break;
  }
  sys_free(io_buf);
  return -1;
}

int32_t file_open(uint32_t inode_NO, uint8_t flag) {
  int fd_idx = get_free_slot_in_global_FT();
  if (fd_idx == -1) {
    printk("exceed max open files\n");
    return -1;
  }
  file_table[fd_idx].fd_flag = flag;
  file_table[fd_idx].fd_inode = inode_open(cur_part, inode_NO);
  file_table[fd_idx].fd_pos = 0;
  bool *write_deny = &file_table[fd_idx].fd_inode->write_deny;

  if (flag & O_WRONLY || flag & O_RDWR) {
    enum intr_status old_status = intr_disable();
    if (!*write_deny) {
      *write_deny = true;
      intr_set_status(old_status);
    } else {
      intr_set_status(old_status);
      printk("file can't be write now, try again later\n");
      return -1;
    }
  }
  return pcb_fd_install(fd_idx);
}

int32_t file_close(struct file *file) {
  if (file == NULL)
    return -1;
  file->fd_inode->write_deny = false;
  inode_close(file->fd_inode);
  file->fd_inode = NULL;
  return 0;
}

int32_t file_write(struct file *file, const void *buf, uint32_t count) {
  if (file->fd_inode->i_size > (BLOCK_SIZE * 140)) {
    printk("exceed max 71680, write file failed\n");
    return -1;
  }

  uint8_t *io_buf = (uint8_t *)sys_malloc(BLOCK_SIZE);
  if (io_buf == NULL) {
    printk("file_write: sys_malloc for io_buf failed\n");
    return -1;
  }

  uint32_t *all_blocks_addr = (uint32_t *)sys_malloc(BLOCK_SIZE + 12 * 4);
  if (io_buf == NULL) {
    printk("file_write: sys_malloc for all_blocks_addr failed\n");
    return -1;
  }

  uint32_t block_LBA = -1;
  uint32_t block_bitmap_idx = 0;
  int32_t indirect_block_table;
  uint32_t block_idx;

  if (file->fd_inode->i_blocks[0] == 0) {
    block_LBA = block_bitmap_alloc(cur_part);
    if (block_LBA == -1) {
      printk("file_write: block_bitmap_alloc failed\n");
      return -1;
    }
    file->fd_inode->i_blocks[0] = block_LBA;
    block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
    ASSERT(block_bitmap_idx != 0);
    bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
  }

  uint32_t file_has_used_blocks = file->fd_inode->i_size / BLOCK_SIZE + 1;
  uint32_t file_will_use_blocks =
      (file->fd_inode->i_size + count) / BLOCK_SIZE + 1;
  ASSERT(file_will_use_blocks < 140);
  uint32_t extra_blocks_required = file_will_use_blocks - file_has_used_blocks;

  if (extra_blocks_required == 0) {
    if (file_has_used_blocks < 12) {
      block_idx = file_has_used_blocks - 1;
      all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];
    } else {
      ASSERT(file->fd_inode->i_blocks[12] != 0);
      indirect_block_table = file->fd_inode->i_blocks[12];
      ide_read(cur_part->which_disk, indirect_block_table, all_blocks_addr + 12,
               1);
    }
  } else {
    if (file_will_use_blocks <= 12) {
      block_idx = file_has_used_blocks - 1;
      ASSERT(file->fd_inode->i_blocks[block_idx] != 0);
      all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];

      block_idx = file_has_used_blocks;
      while (block_idx < file_will_use_blocks) {
        block_LBA = block_bitmap_alloc(cur_part);
        if (block_LBA == -1) {
          printk("file_write: block_bitmap_alloc failed (situation 1)\n");
          return -1;
        }
        ASSERT(file->fd_inode->i_blocks[block_idx] == 0);
        file->fd_inode->i_blocks[block_idx] = all_blocks_addr[block_idx] =
            block_LBA;
        block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        block_idx++;
      }
    } else if (file_has_used_blocks <= 12 && file_will_use_blocks > 12) {
      block_idx = file_has_used_blocks - 1;
      all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];

      block_LBA = block_bitmap_alloc(cur_part);
      if (block_LBA == -1) {
        printk("file_write: block_bitmap_alloc failed (situation 2)\n");
        return -1;
      }
      ASSERT(file->fd_inode->i_blocks[12] == 0);
      indirect_block_table = file->fd_inode->i_blocks[12] = block_LBA;
      block_idx = file_has_used_blocks;

      while (block_idx < file_will_use_blocks) {
        block_LBA = block_bitmap_alloc(cur_part);
        if (block_LBA == -1) {
          printk("file_write: block_bitmap_alloc failed (situation 2)\n");
          return -1;
        }
        if (block_idx < 12) {
          ASSERT(file->fd_inode->i_blocks[block_idx] == 0);
          file->fd_inode->i_blocks[block_idx] = all_blocks_addr[block_idx] =
              block_LBA;
        } else {
          all_blocks_addr[block_idx] = block_LBA;
        }
        block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        block_idx++;
      }
      ide_write(cur_part->which_disk, indirect_block_table,
                all_blocks_addr + 12, 1);
    } else if (file_has_used_blocks > 12) {
      ASSERT(file->fd_inode->i_blocks[12] != 0);
      indirect_block_table = file->fd_inode->i_blocks[12];
      ide_read(cur_part->which_disk, indirect_block_table, all_blocks_addr + 12,
               1);
      block_idx = file_has_used_blocks;
      while (block_idx < file_will_use_blocks) {
        block_LBA = block_bitmap_alloc(cur_part);
        if (block_LBA == -1) {
          printk("file_write: block_bitmap_alloc failed (situation 3)\n");
          return -1;
        }
        all_blocks_addr[block_idx] = block_LBA;
        block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
        bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);
        block_idx++;
      }
      ide_write(cur_part->which_disk, indirect_block_table,
                all_blocks_addr + 12, 1);
    }
  }
  const uint8_t *src = buf;
  uint32_t bytes_left_cnt = count;
  uint32_t sector_idx;
  uint32_t sector_LBA;
  uint32_t offset_bytes_in_sector;
  uint32_t left_bytes_in_sector;
  uint32_t bytes_written_cnt = 0;
  uint32_t chunk_size;

  bool first_write_block = true;

  file->fd_pos = file->fd_inode->i_size - 1;
  while (bytes_written_cnt < count) {
    memset(io_buf, 0, BLOCK_SIZE);
    sector_idx = file->fd_inode->i_size / BLOCK_SIZE;
    sector_LBA = all_blocks_addr[sector_idx];
    offset_bytes_in_sector = file->fd_inode->i_size % BLOCK_SIZE;
    left_bytes_in_sector = BLOCK_SIZE - offset_bytes_in_sector;

    chunk_size = bytes_left_cnt < left_bytes_in_sector ? bytes_left_cnt
                                                       : left_bytes_in_sector;
    if (first_write_block) {
      ide_read(cur_part->which_disk, sector_LBA, io_buf, 1);
      first_write_block = false;
    }
    memcpy(io_buf + offset_bytes_in_sector, src, chunk_size);
    ide_write(cur_part->which_disk, sector_LBA, io_buf, 1);

    printk("file write at LBA 0x%x\n", sector_LBA);
    src += chunk_size;
    file->fd_inode->i_size += chunk_size;
    file->fd_pos += chunk_size;
    bytes_written_cnt += chunk_size;
    bytes_left_cnt -= chunk_size;
  }
  inode_sync(cur_part, file->fd_inode, io_buf);
  sys_free(all_blocks_addr);
  sys_free(io_buf);
  return bytes_written_cnt;
}

int32_t file_read(struct file *file, void *buf, uint32_t count) {
  uint32_t size = count;
  uint32_t size_left = size;

  if ((file->fd_pos + count) > file->fd_inode->i_size) {
    size = file->fd_inode->i_size - file->fd_pos;
    size_left = size;
    if (size == 0)
      return -1;
  }

  uint8_t *io_buf = sys_malloc(BLOCK_SIZE);
  if (io_buf == NULL) {
    printk("file_read: sys_malloc for io_buf failed\n");
  }

  uint32_t *all_blocks_addr = (uint32_t *)sys_malloc(BLOCK_SIZE + 48);
  if (all_blocks_addr == NULL) {
    printk("file_read: sys_malloc for io_buf failed\n");
    return -1;
  }

  uint32_t block_read_start_idx = file->fd_pos / BLOCK_SIZE;
  uint32_t block_read_end_idx = (file->fd_pos + size) / BLOCK_SIZE;
  uint32_t blocks_required_read = block_read_end_idx - block_read_start_idx;
  ASSERT(block_read_start_idx < 139 && block_read_end_idx < 139);

  uint32_t block_idx;
  int32_t indirect_block_table;
  if (blocks_required_read == 0) {
         ASSERT(block_read_start_idx == block_read_end_idx);
    if (block_read_start_idx < 12) {
      block_idx = block_read_start_idx;
      all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];
    } else {
      indirect_block_table = file->fd_inode->i_blocks[12];
      ide_read(cur_part->which_disk, indirect_block_table, all_blocks_addr + 12,
               1);
    }
  } else {
    if (block_read_end_idx < 12) {
      block_idx = block_read_start_idx;
      while (block_idx <= block_read_end_idx) {
        all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];
        block_idx++;
      }
    } else if (block_read_start_idx < 12 && block_read_end_idx >= 12) {
      block_idx = block_read_start_idx;
      while (block_idx < 12) {
        all_blocks_addr[block_idx] = file->fd_inode->i_blocks[block_idx];
        block_idx++;
      }
      ASSERT(file->fd_inode->i_blocks[12] != 0);
      indirect_block_table = file->fd_inode->i_blocks[12];
      ide_read(cur_part->which_disk, indirect_block_table, all_blocks_addr + 12,
               1);
    } else {
      ASSERT(file->fd_inode->i_blocks[12] != 0);
      indirect_block_table = file->fd_inode->i_blocks[12];
      ide_read(cur_part->which_disk, indirect_block_table, all_blocks_addr + 12,
               1);
    }
  }
  uint8_t *dst = buf;
  uint32_t sector_idx;
  uint32_t sector_LBA;
  uint32_t offset_bytes_in_sector;
  uint32_t left_bytes_in_sector;
  uint32_t bytes_read_cnt = 0;
  uint32_t chunk_size;

  while (bytes_read_cnt < size) {
    sector_idx = file->fd_pos / BLOCK_SIZE;
    sector_LBA = all_blocks_addr[sector_idx];
    offset_bytes_in_sector = file->fd_pos % BLOCK_SIZE;
    left_bytes_in_sector = BLOCK_SIZE - offset_bytes_in_sector;

    chunk_size =
        size_left < left_bytes_in_sector ? size_left : left_bytes_in_sector;

    memset(io_buf, 0, BLOCK_SIZE);
    ide_read(cur_part->which_disk, sector_LBA, io_buf, 1);
    memcpy(dst, io_buf + offset_bytes_in_sector, chunk_size);

    dst += chunk_size;
    file->fd_pos += chunk_size;
    bytes_read_cnt += chunk_size;
    size_left -= chunk_size;
  }
  sys_free(all_blocks_addr);
  sys_free(io_buf);
  return bytes_read_cnt;
}
