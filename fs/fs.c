#include "fs.h"
#include "bitmap.h"
#include "console.h"
#include "debug.h"
#include "dir.h"
#include "file.h"
#include "global.h"
#include "ide.h"
#include "inode.h"
#include "io_queue.h"
#include "keyboard.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio_kernel.h"
#include "string.h"
#include "super_block.h"
#include "thread.h"

extern uint8_t channel_cnt;
extern struct ide_channel channels[2];
extern struct list partition_list;
extern struct dir root_dir;
extern struct file file_table[MAX_FILES_OPEN];

struct partition *cur_part;

static bool mount_partition(struct list_elem *pelem, const int arg) {
  char *part_name = (char *)arg;
  struct partition *part = elem2entry(struct partition, part_tag, pelem);

  if (!strcmp(part->name, part_name)) {
    cur_part = part;
    struct disk *hd = cur_part->which_disk;

    struct super_block *_sup_b_buf =
        (struct super_block *)sys_malloc(SECTOR_SIZE);
    cur_part->sup_b =
        (struct super_block *)sys_malloc(sizeof(struct super_block));

    if (cur_part->sup_b == NULL)
      PANIC("allocate memory failed!");

    memset(_sup_b_buf, 0, SECTOR_SIZE);
    ide_read(hd, cur_part->start_LBA + 1, _sup_b_buf, 1);
    memcpy(cur_part->sup_b, _sup_b_buf, sizeof(struct super_block));

    /** printk("part I mounted:\n"); */
    /** printk("  name: %s\n  root_dir_LBA: 0x%x\n  inode_table_LBA: 0x%x\n  "
     */
    /**        "inode_bitmap_LBA: 0x%x\n  free_blocks_bitmap_LBA: 0x%x\n", */
    /**        cur_part->name, cur_part->sup_b->data_start_LBA, */
    /**        cur_part->sup_b->inode_table_LBA,
     * cur_part->sup_b->inode_bitmap_LBA, */
    /**        cur_part->sup_b->free_blocks_bitmap_LBA); */

    cur_part->block_bitmap.bits = (uint8_t *)sys_malloc(
        _sup_b_buf->free_blocks_bitmap_sectors * SECTOR_SIZE);

    if (cur_part->block_bitmap.bits == NULL)
      PANIC("allocate memory failed!");

    cur_part->block_bitmap.bmap_bytes_len =
        _sup_b_buf->free_blocks_bitmap_sectors * SECTOR_SIZE;

    ide_read(hd, _sup_b_buf->free_blocks_bitmap_LBA,
             cur_part->block_bitmap.bits,
             _sup_b_buf->free_blocks_bitmap_sectors);

    cur_part->inode_bitmap.bits =
        (uint8_t *)sys_malloc(_sup_b_buf->inode_bitmap_sectors * SECTOR_SIZE);

    if (cur_part->inode_bitmap.bits == NULL)
      PANIC("allocate memory failed!");

    cur_part->inode_bitmap.bmap_bytes_len =
        _sup_b_buf->inode_bitmap_sectors * SECTOR_SIZE;

    ide_read(hd, _sup_b_buf->inode_bitmap_LBA, cur_part->inode_bitmap.bits,
             _sup_b_buf->inode_bitmap_sectors);

    list_init(&cur_part->open_inodes);
    printk("mount %s done!\n", part->name);
    return true;
  }
  return false;
}


static void partition_format(struct disk *_hd, struct partition *part) {
  uint32_t OS_boot_sectors = 1;

  uint32_t super_block_sectors = 1;

  uint32_t inode_bitmap_sectors =
      DIV_ROUND_UP(MAX_FILES_PER_PART, BITS_PER_SECTOR);

  uint32_t inode_table_sectors =
      DIV_ROUND_UP((sizeof(struct inode) * MAX_FILES_PER_PART), SECTOR_SIZE);

  uint32_t used_sectors = OS_boot_sectors + super_block_sectors +
                          inode_bitmap_sectors + inode_table_sectors;
  uint32_t free_sectors = part->sector_cnt - used_sectors;
  uint32_t free_blocks_bitmap_sectors =
      DIV_ROUND_UP(free_sectors, BITS_PER_SECTOR);
  uint32_t real_free_blocks_sectors = free_sectors - free_blocks_bitmap_sectors;
  free_blocks_bitmap_sectors =
      DIV_ROUND_UP(real_free_blocks_sectors, BITS_PER_SECTOR);
  struct super_block _sup_b;
  _sup_b.magic = 0x20011124;
  _sup_b.sector_cnt = part->sector_cnt;
  _sup_b.inode_cnt = MAX_FILES_PER_PART;
  _sup_b.partition_LBA_addr = part->start_LBA;

  _sup_b.free_blocks_bitmap_LBA = part->start_LBA + 2;
  _sup_b.free_blocks_bitmap_sectors = free_blocks_bitmap_sectors;

  _sup_b.inode_bitmap_LBA =
      _sup_b.free_blocks_bitmap_LBA + _sup_b.free_blocks_bitmap_sectors;
  _sup_b.inode_bitmap_sectors = inode_bitmap_sectors;

  _sup_b.inode_table_LBA =
      _sup_b.inode_bitmap_LBA + _sup_b.inode_bitmap_sectors;
  _sup_b.inode_table_sectors = inode_table_sectors;

  _sup_b.data_start_LBA = _sup_b.inode_table_LBA + _sup_b.inode_table_sectors;
  _sup_b.root_inode_NO = 0;
  _sup_b.dir_entry_size = sizeof(struct dir_entry);

  printk("%s info:\n", part->name);
  printk("  magic:0x%x\n  partition_LBA_addr:0x%x\n  total_sectors:0x%x\n  "
         "inode_cnt:0x%x\n  free_blocks_bitmap_LBA:0x%x\n  "
         "free_blocks_bitmap_sectors:0x%x\n  inode_bitmap_LBA:0x%x\n  "
         "inode_bitmap_sectors:0x%x\n  inode_table_LBA:0x%x\n  "
         "inode_table_sectors:0x%x\n  data_start_LBA:0x%x\n",
         _sup_b.magic, _sup_b.partition_LBA_addr, _sup_b.sector_cnt,
         _sup_b.inode_cnt, _sup_b.free_blocks_bitmap_LBA,
         _sup_b.free_blocks_bitmap_sectors, _sup_b.inode_bitmap_LBA,
         _sup_b.inode_bitmap_sectors, _sup_b.inode_table_LBA,
         _sup_b.inode_table_sectors, _sup_b.data_start_LBA);

  struct disk *hd = part->which_disk;
  ide_write(hd, part->start_LBA + 1, &_sup_b, 1);
  printk("  super_block_LBA:0x%x\n", part->start_LBA + 1);

  uint32_t buf_size =
      (_sup_b.free_blocks_bitmap_sectors > _sup_b.inode_bitmap_sectors
           ? _sup_b.free_blocks_bitmap_sectors
           : _sup_b.inode_bitmap_sectors);

  buf_size =(buf_size > _sup_b.inode_table_sectors
             ? buf_size
             : _sup_b.inode_table_sectors)
             * SECTOR_SIZE;
  uint8_t *buf = (uint8_t *)sys_malloc(buf_size);

  buf[0] |= 0x01;
  uint32_t free_blocks_bitmap_last_byte = real_free_blocks_sectors / 8;
  uint32_t free_blocks_bitmap_last_effective_bit = real_free_blocks_sectors % 8;
  uint32_t bitmap_last_sector_unused_space =
      SECTOR_SIZE - (free_blocks_bitmap_last_byte % SECTOR_SIZE);
  memset(&buf[free_blocks_bitmap_last_byte], 0xff,
         bitmap_last_sector_unused_space);
  uint8_t bit_idx = 0;
  while (bit_idx <= free_blocks_bitmap_last_effective_bit) {
    buf[free_blocks_bitmap_last_byte] &= ~(1 << bit_idx++);
  }
  ide_write(hd, _sup_b.free_blocks_bitmap_LBA, buf,
            _sup_b.free_blocks_bitmap_sectors);

  memset(buf, 0, buf_size);
  buf[0] |= 0x01;
  ide_write(hd, _sup_b.inode_bitmap_LBA, buf, _sup_b.inode_bitmap_sectors);

  memset(buf, 0, buf_size);
  struct inode *i = (struct inode *)buf;
  i->i_NO = 0;
  i->i_size = _sup_b.dir_entry_size * 2;
  i->i_blocks[0] = _sup_b.data_start_LBA;
  ide_write(hd, _sup_b.inode_table_LBA, buf, _sup_b.inode_table_sectors);

  memset(buf, 0, buf_size);
  struct dir_entry *de = (struct dir_entry *)buf;
  memcpy(de->filename, ".", 1);
  de->f_type = FT_DIRECTORY;
  de->i_NO = 0;
  de++;
  memcpy(de->filename, "..", 2);
  de->f_type = FT_DIRECTORY;
  de->i_NO = 0;

  ide_write(hd, _sup_b.data_start_LBA, buf, 1);

  printk("  root_dir_LBA:0x%x\n", _sup_b.data_start_LBA);
  printk("  %s format done\n", part->name);
}

void filesys_init() {
  uint8_t channel_NO = 0, part_idx = 0;
  uint8_t dev_NO;
  struct super_block *_sup_b_buf =
      (struct super_block *)sys_malloc(SECTOR_SIZE);
  if (_sup_b_buf == NULL)
    PANIC("allocate memory failed!");
  printk("searching filesystem......\n");
  while (channel_NO < channel_cnt) {
    dev_NO = 0;
    while (dev_NO < 2) {
      if (dev_NO == 0) {
        dev_NO++;
        continue;
      }
      struct disk *hd = &channels[channel_NO].devices[dev_NO];
      struct partition *part = hd->prim_parts;
      while (part_idx < 12) {
        if (part_idx == 4) {
          part = hd->logic_parts;
        }
        if (part->sector_cnt != 0) {
          memset(_sup_b_buf, 0, SECTOR_SIZE);
          ide_read(hd, part->start_LBA + 1, _sup_b_buf, 1);
          if (_sup_b_buf->magic == 0x20011124) {
            printk("%s has filesystem\n", part->name);
          } else {
            printk("fromatting %s's partition %s......\n", hd->name,
                   part->name);
            partition_format(hd, part);
          }
        }
        part_idx++;
        part++;
      }
      dev_NO++;
    }
    channel_NO++;
  }
  sys_free(_sup_b_buf);

  char default_part[8] = "sdb1";
  list_traversal(&partition_list, mount_partition, (int)default_part);

  open_root_dir(cur_part);
  uint32_t fd_idx = 0;
  while (fd_idx < MAX_FILES_OPEN) {
    file_table[fd_idx++].fd_inode = NULL;
  }
}

char *path_parse(char *pathname, char *name_buf) {
  if (pathname[0] == '/') {
    while (*(++pathname) == '/')
      ;
  }
  while (*pathname != '/' && *pathname != '\0') {
    *name_buf++ = *pathname++;
  }
  if (pathname[0] == '\0') {
    return NULL;
  }

  return pathname;
}

int32_t path_depth_cnt(char *pathname) {
  ASSERT(pathname != NULL);
  char *p = pathname;
  char name_buf[MAX_FILE_NAME_LEN];
  uint32_t depth = 0;

  p = path_parse(p, name_buf);
  while (*name_buf) {
    depth++;
    memset(name_buf, 0, MAX_FILE_NAME_LEN);
    if (p) {
      p = path_parse(p, name_buf);
    }
  }
  return depth;
}

static int search_file(const char *pathname,
                       struct path_search_record *searched_record) {
  if (!strcmp(pathname, "/") || !strcmp(pathname, "/.") ||
      !strcmp(pathname, "/..")) {
    searched_record->searched_path[0] = 0;
    searched_record->parent_dir = &root_dir;
    searched_record->file_type = FT_DIRECTORY;
    return 0;
  }
  uint32_t path_len = strlen(pathname);
  ASSERT(pathname[0] == '/' && path_len > 1 && path_len < MAX_PATH_LEN);

  char *sub_path = (char *)pathname;
  char name_buf[MAX_FILE_NAME_LEN] = {0};
  struct dir *parent_dir = &root_dir;
  searched_record->parent_dir = parent_dir;
  struct dir_entry dir_e;
  searched_record->file_type = FT_UNKNOWN;
  uint32_t parent_inode_NO = 0;

  sub_path = path_parse(sub_path, name_buf);

  while (*name_buf) {
    ASSERT(strlen(searched_record->searched_path) < 512);
    strcat(searched_record->searched_path, "/");
    strcat(searched_record->searched_path, name_buf);

    if (search_dir_entry(cur_part, parent_dir, name_buf, &dir_e)) {
      memset(name_buf, 0, MAX_FILE_NAME_LEN);
      if (sub_path) {
        sub_path = path_parse(sub_path, name_buf);
      }

      if (dir_e.f_type == FT_DIRECTORY) {
        parent_inode_NO = parent_dir->_inode->i_NO;
        dir_close(parent_dir);
        parent_dir = dir_open(cur_part, dir_e.i_NO);
        searched_record->parent_dir = parent_dir;
        continue;
      } else if (dir_e.f_type == FT_REGULAR) {
        searched_record->file_type = FT_REGULAR;
        return dir_e.i_NO;
      }
    } else {
      return -1;
    }
  }
  dir_close(searched_record->parent_dir);
  searched_record->parent_dir = dir_open(cur_part, parent_inode_NO);
  searched_record->file_type = FT_DIRECTORY;
  return dir_e.i_NO;
}
int32_t sys_open(const char *pathname, uint8_t flag) {
  if (pathname[strlen(pathname) - 1] == '/') {
    printk("sys_open: Can't open a directory %s\n", pathname);
    return -1;
  }
  ASSERT(flag < 0b1000);
  int32_t fd = -1;

  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));

  uint32_t pathname_depth = path_depth_cnt((char *)pathname);

  int inode_NO = search_file(pathname, &searched_record);
  bool found = inode_NO != -1 ? true : false;

  if (searched_record.file_type == FT_DIRECTORY) {
    printk(
        "sys_open: Can't open a directory with open(), user opendir instead\n");
    dir_close(searched_record.parent_dir);
    return -1;
  }

  uint32_t path_searched_depth = path_depth_cnt(searched_record.searched_path);
  if (path_searched_depth != pathname_depth) {
    printk(
        "sys_open: Cannot access %s: Not a directory, subpath %s is't exist\n",
        pathname, searched_record.searched_path);
    dir_close(searched_record.parent_dir);
    return -1;
  }

  if (!found && !(flag & O_CREAT)) {
    printk("sys_open: In path %s,file %s is't exist\n",
           searched_record.searched_path,
           (strrchr(searched_record.searched_path, '/') + 1));
    dir_close(searched_record.parent_dir);
    return -1;
  } else if (found && flag & O_CREAT) {
    printk("%s has already exist!\n", pathname);
    dir_close(searched_record.parent_dir);
    return -1;
  }

  switch (flag & O_CREAT) {
  case O_CREAT:
    printk("creating file\n");
    fd = file_create(searched_record.parent_dir, (strrchr(pathname, '/') + 1),
                     flag);
    dir_close(searched_record.parent_dir);
    break;
  default:
    fd = file_open(inode_NO, flag);
  }
  return fd;
}

static uint32_t fd_local_2_global(uint32_t local_fd_idx) {
  struct task_struct *cur = running_thread();
  int32_t global_fd_idx = cur->fd_table[local_fd_idx];
  ASSERT(global_fd_idx >= 0 && global_fd_idx < MAX_FILES_OPEN);
  return (uint32_t)global_fd_idx;
}

int32_t sys_close(int32_t fd) {
  int32_t ret = -1;
  if (fd > 2) {
    uint32_t _fd = fd_local_2_global(fd);
    ret = file_close(&file_table[_fd]);
    running_thread()->fd_table[fd] = -1;
  }
  return ret;
}

uint32_t sys_write(int32_t fd, const void *buf, uint32_t count) {
  if (fd < 0) {
    printk("sys_write: fd error\n");
    return -1;
  }

  if (fd == STDOUT_NO) {
    char io_buf[1024] = {0};
    memcpy(io_buf, buf, count);
    console_put_str(io_buf);
    return count;
  }

  uint32_t _fd = fd_local_2_global(fd);
  struct file *wr_file = &file_table[_fd];
  if (wr_file->fd_flag & O_WRONLY || wr_file->fd_flag & O_RDWR) {
    uint32_t bytes_written = file_write(wr_file, buf, count);
    return bytes_written;
  } else {
    console_put_str("sys_write: not allowed to write file without flag "
                    "O_WRONLY or O_RDWR\n");
    return -1;
  }
}

int32_t sys_read(int32_t fd, void *buf, uint32_t count) {
  ASSERT(buf != NULL);
  int ret_val = -1;
  if (fd < 0 || fd == STDOUT_NO || fd == STDERR_NO) {
    printk("sys_read: fd error\n");
  } else if (fd == STDIN_NO) {
    char *buffer = buf;
    uint32_t bytes_read = 0;
    while (bytes_read < count) {
      *buffer = ioq_getchar(&kbd_circular_buf);
      bytes_read++;
      buffer++;
    }
    ret_val = (bytes_read == 0) ? -1 : (int32_t)bytes_read;
  } else {
    uint32_t _fd = fd_local_2_global(fd);
    ret_val = file_read(&file_table[_fd], buf, count);
  }
  return ret_val;
}

int32_t sys_lseek(int32_t fd, int32_t offset, uint8_t whence) {
  if (fd < 0) {
    printk("sys_lseek: fd error\n");
    return -1;
  }

  ASSERT(whence < 4);
  uint32_t _fd = fd_local_2_global(fd);
  struct file *pf = &file_table[_fd];
  int32_t new_fd_pos = 0;
  int32_t file_size = pf->fd_inode->i_size;
  switch (whence) {
  case SEEK_SET:
    new_fd_pos = offset;
    break;
  case SEEK_CUR:
    new_fd_pos = (int32_t)pf->fd_pos + offset;
    break;
  case SEEK_END:
    new_fd_pos = file_size + offset;
  }

  if (new_fd_pos < 0 || new_fd_pos > (file_size - 1))
    return -1;

  pf->fd_pos = new_fd_pos;
  return pf->fd_pos;
}

int32_t sys_unlink(const char *pathname) {
  ASSERT(strlen(pathname) < MAX_PATH_LEN);
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  int inode_NO = search_file(pathname, &searched_record);
  ASSERT(inode_NO != 0);
  if (inode_NO == -1) {
    printk("file %s not found!\n", pathname);
    dir_close(searched_record.parent_dir);
    return -1;
  }
  if (searched_record.file_type == FT_DIRECTORY) {
    printk("can't delete a directory with unlink() ,use rmdir() instead\n");
    dir_close(searched_record.parent_dir);
    return -1;
  }
  uint32_t file_idx = 0;
  while (file_idx < MAX_FILES_OPEN) {
    if (file_table[file_idx].fd_inode != NULL &&
        (uint32_t)inode_NO == file_table[file_idx].fd_inode->i_NO) {
      break;
    }
    file_idx++;
  }
  if (file_idx < MAX_FILES_OPEN) {
    dir_close(searched_record.parent_dir);
    printk("file %s is in use, not allow to delete!\n", pathname);
    return -1;
  }

  ASSERT(file_idx == MAX_FILES_OPEN);
  void *io_buf = sys_malloc(SECTOR_SIZE * 2);
  if (io_buf == NULL) {
    dir_close(searched_record.parent_dir);
    printk("sys_unlink: sys_malloc for io_buf failed\n");
    return -1;
  }

  struct dir *parent_dir = searched_record.parent_dir;
  delete_dir_entry(cur_part, parent_dir, inode_NO, io_buf);

  inode_release(cur_part, inode_NO);
  sys_free(io_buf);
  dir_close(searched_record.parent_dir);
  return 0;
}
int32_t sys_mkdir(const char *pathname) {
  uint32_t rollback_action = 0;

  void *io_buf = sys_malloc(SECTOR_SIZE * 2);
  if (io_buf == NULL) {
    printk("sys_mkdir: sys_malloc for io_buf failed\n");
    return -1;
  }
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  int inode_NO = -1;
  inode_NO = search_file(pathname, &searched_record);
  if (inode_NO != -1) {
    printk("sys_mkdir: directory %s already exists!\n");
    rollback_action = 2;
    goto rollback;
  } else {
    uint32_t pathname_depth = path_depth_cnt((char *)pathname);
    uint32_t path_searched_depth =
        path_depth_cnt(searched_record.searched_path);
    if (pathname_depth != path_searched_depth) {
      printk("sys_mkdir: cannot access %s: subpath %s is't "
             "exist\n",
             pathname, searched_record.searched_path);
      rollback_action = 2;
      goto rollback;
    }
  }

  struct dir *parent_dir = searched_record.parent_dir;
  char *dirname = strrchr(searched_record.searched_path, '/') + 1;

  int new_inode_NO = inode_bitmap_alloc(cur_part);
  if (new_inode_NO == -1) {
    printk("sys_mkdir: allocate inode failed\n");
    rollback_action = 2;
    goto rollback;
  }
  struct inode new_dir_inode;
  inode_init(new_inode_NO, &new_dir_inode);

  uint32_t block_bitmap_idx = 0;
  int32_t block_LBA = -1;
  block_LBA = block_bitmap_alloc(cur_part);
  if (block_LBA == -1) {
    printk("sys_mkdir: block_bitmap_alloc for create directory failed\n");
    rollback_action = 1;
    goto rollback;
  }
  new_dir_inode.i_blocks[0] = block_LBA;
  block_bitmap_idx = block_LBA - cur_part->sup_b->data_start_LBA;
  ASSERT(block_bitmap_idx != 0);
  bitmap_sync(cur_part, block_bitmap_idx, BLOCK_BITMAP);

  memset(io_buf, 0, SECTOR_SIZE * 2);
  struct dir_entry *de = (struct dir_entry *)io_buf;
  memcpy(de->filename, ".", 1);
  de->f_type = FT_DIRECTORY;
  de->i_NO = new_inode_NO;
  de++;
  memcpy(de->filename, "..", 2);
  de->f_type = FT_DIRECTORY;
  de->i_NO = parent_dir->_inode->i_NO;
  ide_write(cur_part->which_disk, new_dir_inode.i_blocks[0], io_buf, 1);
  new_dir_inode.i_size += 2 * cur_part->sup_b->dir_entry_size;

  struct dir_entry new_dir_entry;
  memset(&new_dir_entry, 0, sizeof(struct dir_entry));
  create_dir_entry(dirname, new_inode_NO, FT_DIRECTORY, &new_dir_entry);
  memset(io_buf, 0, SECTOR_SIZE * 2);
  if (!sync_dir_entry(parent_dir, &new_dir_entry, io_buf)) {
    printk("sys_mkdir: sync_dir_entry to disk failed\n");
    rollback_action = 1;
    goto rollback;
  }
  memset(io_buf, 0, SECTOR_SIZE * 2);
  inode_sync(cur_part, parent_dir->_inode, io_buf);
  memset(io_buf, 0, SECTOR_SIZE * 2);
  inode_sync(cur_part, &new_dir_inode, io_buf);
  bitmap_sync(cur_part, new_inode_NO, INODE_BITMAP);

  sys_free(io_buf);
  dir_close(parent_dir);
  return 0;

rollback:
  switch (rollback_action) {
  case 1:
    bitmap_set(&cur_part->inode_bitmap, inode_NO, 0);
  case 2:
    dir_close(searched_record.parent_dir);
    break;
  }
  sys_free(io_buf);
  return -1;
}

struct dir *sys_opendir(const char *name) {
  ASSERT(strlen(name) < MAX_PATH_LEN);

  if (name[0] == '/') {
    if (name[1] == 0 || (name[1] == '.' && name[2] == 0) ||
        (name[1] == '.' && name[2] == '.' && name[3] == 0)) {
      return &root_dir;
    }
  }

  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  struct dir *target_dir_ptr = NULL;
  int inode_NO = search_file(name, &searched_record);
  if (inode_NO == -1) {
    printk("In %s, subpath %s not exitts\n", name,
           searched_record.searched_path);
  } else {
    if (searched_record.file_type == FT_REGULAR) {
      printk("%s is regular file!\n", name);
    } else if (searched_record.file_type == FT_DIRECTORY) {
      target_dir_ptr = dir_open(cur_part, inode_NO);
    }
  }
  dir_close(searched_record.parent_dir);
  return target_dir_ptr;
}
-1 if an error occurred or if 'dir' is NULL.
int32_t sys_closedir(struct dir *dir) {
  int32_t ret = -1;
  if (dir != NULL) {
    dir_close(dir);
    ret = 0;
  }
  return ret;
}

struct dir_entry *sys_readdir(struct dir *dir) {
  ASSERT(dir != NULL);
  return dir_read(dir);
}

void sys_rewinddir(struct dir *dir) { dir->dir_pos = 0; }

int32_t sys_rmdir(const char *pathname) {
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));

  int inode_NO = search_file(pathname, &searched_record);
  ASSERT(inode_NO != 0);

  int ret_val = -1;
  if (inode_NO == -1) {
    printk("In %s, subpath %s not exist\n", pathname,
           searched_record.searched_path);
  } else {
    if (searched_record.file_type == FT_REGULAR) {
      printk("%s is regular file\n", pathname);
    } else {
      struct dir *dir = dir_open(cur_part, inode_NO);
      if (!dir_is_empty(dir)) {
        printk("Directory %s is not empty\n", pathname);
      } else {
        if (!dir_remove(searched_record.parent_dir, dir)) {
          ret_val = 0;
        }
      }
      dir_close(dir);
    }
  }
  dir_close(searched_record.parent_dir);
  return ret_val;
}

static uint32_t get_parent_dir_inode_NO(uint32_t child_dir_inode_NO,
                                        void *io_buf) {
  struct inode *child_dir_inode = inode_open(cur_part, child_dir_inode_NO);

  uint32_t block_LBA = child_dir_inode->i_blocks[0];
  ASSERT(block_LBA >= cur_part->sup_b->data_start_LBA);
  ide_read(cur_part->which_disk, block_LBA, io_buf, 1);
  inode_close(child_dir_inode);

  struct dir_entry *dir_entry_iter = (struct dir_entry *)io_buf;
  ASSERT(dir_entry_iter->i_NO < 4096 &&
         dir_entry_iter[1].f_type == FT_DIRECTORY);

  return dir_entry_iter[1].i_NO;
}

static int get_child_dir_name(uint32_t p_inode_NO, uint32_t c_inode_NO,
                              char *path, void *io_buf) {
  struct inode *parent_dir_inode = inode_open(cur_part, p_inode_NO);

  uint8_t block_idx = 0;
  uint32_t all_blocks_addr[140], block_cnt = 12;
  while (block_idx < 12) {
    all_blocks_addr[block_idx] = parent_dir_inode->i_blocks[block_idx];
    block_idx++;
  }

  if (parent_dir_inode->i_blocks[12] != 0) {
    ide_read(cur_part->which_disk, parent_dir_inode->i_blocks[12],
             all_blocks_addr + 12, 1);
    block_cnt += 128;
  }
  inode_close(parent_dir_inode);

  struct dir_entry *dir_entry_base = (struct dir_entry *)io_buf;
  uint32_t _dir_entry_size = cur_part->sup_b->dir_entry_size;
  uint32_t max_dir_entry_per_sector = SECTOR_SIZE / _dir_entry_size;
  block_idx = 0;
  while (block_idx < block_cnt) {
    if (all_blocks_addr[block_idx] != 0) {
      ide_read(cur_part->which_disk, all_blocks_addr[block_idx], io_buf, 1);
      uint8_t dir_entry_idx = 0;
      while ((dir_entry_idx < max_dir_entry_per_sector)) {
        if ((dir_entry_base + dir_entry_idx)->i_NO == c_inode_NO) {
          strcat(path, "/");
          strcat(path, (dir_entry_base + dir_entry_idx)->filename);
          return 0;
        }
        /* next dir entry within the same block  */
        dir_entry_idx++;
      }
    }
    block_idx++;
  }
  return -1;
}

char *sys_getcwd(char *buf, uint32_t size) {
  ASSERT(buf != NULL);
  void *io_buf = sys_malloc(SECTOR_SIZE);
  if (io_buf == NULL)
    return NULL;

  struct task_struct *cur_thread = running_thread();
  int32_t parent_inode_NO = 0;
  int32_t child_dir_inode_NO = cur_thread->cwd_inode_NO;
  ASSERT(child_dir_inode_NO >= 0 && child_dir_inode_NO < 4096);

  if (child_dir_inode_NO == 0) {
    buf[0] = '/';
    buf[1] = 0;
    return buf;
  }

  memset(buf, 0, size);
  char full_path_reverse[MAX_PATH_LEN] = {0};

  while (((child_dir_inode_NO != 0))) {
    parent_inode_NO = get_parent_dir_inode_NO(child_dir_inode_NO, io_buf);
    if (get_child_dir_name(parent_inode_NO, child_dir_inode_NO,
                           full_path_reverse, io_buf) == -1) {
      sys_free(io_buf);
      return NULL;
    }
    child_dir_inode_NO = parent_inode_NO;
  }

  ASSERT(strlen(full_path_reverse) <= size);
  char *last_slash;
  while (((last_slash = strrchr(full_path_reverse, '/')))) {
    uint16_t len = strlen(buf);
    strcpy(buf + len, last_slash);
    *last_slash = 0;
  }
  sys_free(io_buf);
  return buf;
}

int32_t sys_chdir(const char *path) {
  int32_t ret = -1;
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  int inode_NO = search_file(path, &searched_record);
  if (inode_NO != -1) {
    if (searched_record.file_type == FT_DIRECTORY) {
      running_thread()->cwd_inode_NO = inode_NO;
      ret = 0;
    } else {
      printk("sys_chdir: %s is not a directory!\n", path);
    }
  }
  dir_close(searched_record.parent_dir);
  return ret;
}

int32_t sys_stat(const char *path, struct stat *buf) {
  if (!strcmp(path, "/") || !strcmp(path, "/.") || !strcmp(path, "/..")) {
    buf->st_filetype = FT_DIRECTORY;
    buf->st_ino = 0;
    buf->st_size = root_dir._inode->i_size;
    return 0;
  }

  int32_t ret_val = -1;
  struct path_search_record searched_record;
  memset(&searched_record, 0, sizeof(struct path_search_record));
  int inode_NO = search_file(path, &searched_record);
  if (inode_NO != -1) {
    struct inode *target_inode = inode_open(cur_part, inode_NO);
    buf->st_size = target_inode->i_size;
    buf->st_filetype = searched_record.file_type;
    buf->st_ino = inode_NO;
    inode_close(target_inode);
    ret_val = 0;
  }
  dir_close(searched_record.parent_dir);
  return ret_val;
}
