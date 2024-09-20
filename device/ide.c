#include "ide.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "io.h"
#include "list.h"
#include "memory.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_kernel.h"
#include "string.h"
#include "sync.h"
#include "timer.h"

#define reg_data(channel) (channel->port_base + 0)
#define reg_error(channel) (channel->port_base + 1)
#define reg_sector_cnt(channel) (channel->port_base + 2)
#define reg_LBA_l(channel) (channel->port_base + 3)
#define reg_LBA_m(channel) (channel->port_base + 4)
#define reg_LBA_h(channel) (channel->port_base + 5)
#define reg_device(channel) (channel->port_base + 6)
#define reg_status(channel) (channel->port_base + 7)
#define reg_cmd(channel) (reg_status(channel))
#define reg_altne_status(channel) (channel->port_base + 0x206)
#define reg_ctl(channel) (reg_alte_status(channel))

#define BIT_STAT_BUSY 0x80
#define BIT_STAT_DRDY 0x40
#define BIT_STAT_DREQ 0x08
#define BIT_DEV_MBS 0xa0
#define BIT_DEV_LBA 0x40
#define BIT_DEV_SLAVE 0x10

#define CMD_IDENTIFY 0xec
#define CMD_READ_SECTOR 0x20
#define CMD_WRITE_SECTOR 0x30

#define MAX_LBA ((80 * 1024 * 1024 / 512) - 1)

uint8_t channel_cnt;
struct ide_channel channels[2];

int32_t ext_LBA_benchmark = 0;
uint8_t primary_disk_NO = 0, logical_disk_NO = 0;
struct list partition_list;

struct partition_table_entry {
  uint8_t bootable;
  uint8_t start_head;
  uint8_t start_sector;
  uint8_t start_CHS;
  uint8_t fs_type;
  uint8_t end_head;
  uint8_t end_sector;
  uint8_t end_CHS;

  uint32_t start_offset_LBA;
  uint32_t sector_cnt;
} __attribute__((packed));

struct boot_sector {
  uint8_t other[446];
  struct partition_table_entry partition_table[4];
  uint16_t signature;
} __attribute__((packed));


static void swap_pairs_bytes(const char *dst, char *buf, uint32_t len) {
  uint8_t idx;
  for (idx = 0; idx < len; idx += 2) {
    buf[idx + 1] = *dst++;
    buf[idx] = *dst++;
  }
  buf[idx] = '\0';
}

static void select_disk(struct disk *hd) {
  uint8_t reg_device = BIT_DEV_MBS | BIT_DEV_LBA;
  if (hd->dev_NO == 1)
    reg_device |= BIT_DEV_SLAVE;
  outb(reg_device(hd->which_channel), reg_device);
}

static void select_sector(struct disk *hd, uint32_t LBA, uint8_t sector_cnt) {
  ASSERT(LBA <= MAX_LBA);

  struct ide_channel *channel = hd->which_channel;
  outb(reg_sector_cnt(channel), sector_cnt);

  outb(reg_LBA_l(channel), LBA);
  outb(reg_LBA_m(channel), LBA >> 8);
  outb(reg_LBA_h(channel), LBA >> 16);
  outb(reg_device(channel), BIT_DEV_MBS | BIT_DEV_LBA |
                                (hd->dev_NO == 1 ? BIT_DEV_SLAVE : 0) |
                                LBA >> 24);
}

static void cmd_out(struct ide_channel *channel, uint8_t cmd) {
  channel->expecting_intr = true;
  outb(reg_cmd(channel), cmd);
}
static void read_from_sector(struct disk *hd, void *buf, uint8_t sector_cnt) {
  uint32_t size_in_byte;
  if (sector_cnt == 0) {
    size_in_byte = 256 * 512;
  } else {
    size_in_byte = sector_cnt * 512;
  }
  insw(reg_data(hd->which_channel), buf, size_in_byte / 2);
}

static void write_to_sector(struct disk *hd, void *buf, uint8_t sector_cnt) {
  uint32_t size_in_byte;
  if (sector_cnt == 0) {
    size_in_byte = 256 * 512;
  } else {
    size_in_byte = sector_cnt * 512;
  }
  outsw(reg_data(hd->which_channel), buf, size_in_byte / 2);
}

static bool busy_wait(struct disk *hd) {
  struct ide_channel *channel = hd->which_channel;
  uint16_t time_limit = 30 * 1000;

  while (time_limit -= 10 >= 0) {
    if (!(inb(reg_status(channel)) & BIT_STAT_BUSY)) {
      return (inb(reg_status(channel)) & BIT_STAT_DREQ);
    } else {
      mtime_sleep(10);
    }
  }
  return false;
}

void ide_read(struct disk *hd, uint32_t LBA, void *buf, uint32_t sector_cnt) {
  ASSERT(LBA <= MAX_LBA && sector_cnt > 0);
  lock_acquire(&hd->which_channel->_lock);
  select_disk(hd);

  uint32_t sector_operate;
  uint32_t sector_done = 0;
  while (sector_done < sector_cnt) {
    if ((sector_done + 256) <= sector_cnt) {
      sector_operate = 256;
    } else {
      sector_operate = sector_cnt - sector_done;
    }

    select_sector(hd, LBA + sector_done, sector_operate);
    cmd_out(hd->which_channel, CMD_READ_SECTOR);

    sema_down(&hd->which_channel->disk_done);


    if (!busy_wait(hd)) {
      char error_msg[64];
      sprintf(error_msg, "%s read sector %d failed!!!!!!\n", hd->name, LBA);
      PANIC(error_msg);
    }

    read_from_sector(hd, (void *)((uint32_t)buf + sector_done * 512),
                     sector_operate);
    sector_done += sector_operate;
  }
  lock_release(&hd->which_channel->_lock);
}


void ide_write(struct disk *hd, uint32_t LBA, void *buf, uint32_t sector_cnt) {
  ASSERT(LBA <= MAX_LBA && sector_cnt > 0);
  lock_acquire(&hd->which_channel->_lock);
  select_disk(hd);

  uint32_t sector_operate;
  uint32_t sector_done = 0;
  while (sector_done < sector_cnt) {
    if ((sector_done + 256) <= sector_cnt) {
      sector_operate = 256;
    } else {
      sector_operate = sector_cnt - sector_done;
    }

    select_sector(hd, LBA + sector_done, sector_operate);
    cmd_out(hd->which_channel, CMD_WRITE_SECTOR);

    if (!busy_wait(hd)) {
      char error_msg[64];
      sprintf(error_msg, "%s write sector %d failed!!!!!!\n", hd->name, LBA);
      PANIC(error_msg);
    }

    write_to_sector(hd, (void *)((uint32_t)buf + sector_done * 512),
                    sector_operate);
    sema_down(&hd->which_channel->disk_done);
    sector_done += sector_operate;
  }
  lock_release(&hd->which_channel->_lock);
}

void intr_hd_handler(uint8_t _IRQ_NO) {
  ASSERT(_IRQ_NO == 0x2e || _IRQ_NO == 0x2f);
  uint8_t channel_NO = _IRQ_NO - 0x2e;
  struct ide_channel *channel = &channels[channel_NO];
  ASSERT(channel->IRQ_NO == _IRQ_NO);

  if (channel->expecting_intr) {
    channel->expecting_intr = false;
    sema_up(&channel->disk_done);

    inb(reg_status(channel));
  }
}

static void identify_disk(struct disk *hd) {
  char id_info[512];
  select_disk(hd);
  cmd_out(hd->which_channel, CMD_IDENTIFY);

  sema_down(&hd->which_channel->disk_done);

  if (!busy_wait(hd)) {
    char error_msg[64];
    sprintf(error_msg, "%s identify failed!!!!!!\n", hd->name);
    PANIC(error_msg);
  }
  read_from_sector(hd, id_info, 1);

  char buf[64];
  uint8_t serial_num_start = 10 * 2, serial_num_len = 20;
  uint8_t model_start = 27 * 2, model_len = 40;
  uint8_t sector_cnt_start = 60 * 2;
  swap_pairs_bytes(&id_info[serial_num_start], buf, serial_num_len);
  printk(" disk %s info:\n      Serial-Number: %s\n", hd->name, buf);
  memset(buf, 0, sizeof(buf));
  swap_pairs_bytes(&id_info[model_start], buf, model_len);
  printk("      Model: %s\n", buf);
  uint32_t sectors = *((uint32_t *)&id_info[sector_cnt_start]);
  printk("      CAPACITY: %dMB\n", sectors * 512 / 1024 / 1024);
}

static void partition_scan(struct disk *hd, uint32_t _LBA) {
  struct boot_sector *bs = sys_malloc(sizeof(struct boot_sector));
  ide_read(hd, _LBA, bs, 1);
  uint8_t part_idx = 0;
  struct partition_table_entry *p = bs->partition_table;

  while (part_idx++ < 4) {
    if (p->fs_type == 0x5) {
      if (ext_LBA_benchmark != 0) {
        partition_scan(hd, p->start_offset_LBA + ext_LBA_benchmark);
      } else {
        ext_LBA_benchmark = p->start_offset_LBA;

        partition_scan(hd, p->start_offset_LBA);
      }
    } else if (p->fs_type != 0) {
      if (_LBA == 0) {
        hd->prim_parts[primary_disk_NO].start_LBA = p->start_offset_LBA;

        hd->prim_parts[primary_disk_NO].sector_cnt = p->sector_cnt;
        hd->prim_parts[primary_disk_NO].which_disk = hd;

        list_append(&partition_list, &hd->prim_parts[primary_disk_NO].part_tag);
        sprintf(hd->prim_parts[primary_disk_NO].name, "%s%d", hd->name,
                primary_disk_NO + 1);
        primary_disk_NO++;
        ASSERT(primary_disk_NO < 4);
      } else {
        hd->logic_parts[logical_disk_NO].start_LBA = _LBA + p->start_offset_LBA;

        hd->logic_parts[logical_disk_NO].sector_cnt = p->sector_cnt;
        hd->logic_parts[logical_disk_NO].which_disk = hd;
        list_append(&partition_list,
                    &hd->logic_parts[logical_disk_NO].part_tag);
        sprintf(hd->logic_parts[logical_disk_NO].name, "%s%d", hd->name,
                logical_disk_NO + 5);
        logical_disk_NO++;
        if (logical_disk_NO >= 8)
          return;
      }
    }
    p++;
  }
  sys_free(bs);
}

static bool print_partition_info(struct list_elem *pelem, int arg UNUSED) {
  struct partition *part = elem2entry(struct partition, part_tag, pelem);
  printk("   %s start_LBA:0x%x, sector_cnt:0x%x\n", part->name, part->start_LBA,
         part->sector_cnt);
  return false;
}

void ide_init() {
  printk("ide_init start\n");
  uint8_t hd_cnt = *((uint8_t *)0x475);
  ASSERT(hd_cnt > 0);
  list_init(&partition_list);
  channel_cnt = DIV_ROUND_UP(hd_cnt, 2);

  struct ide_channel *channel;
  uint8_t channel_NO = 0;
  uint8_t dev_NO = 0;
  while (channel_NO < channel_cnt) {
    channel = &channels[channel_NO];
    sprintf(channel->name, "ide%d", channel_NO);
    switch (channel_NO) {
    case 0:
      channel->port_base = 0x1f0;
      channel->IRQ_NO = 0x20 + 14;
      break;
    case 1:
      channel->port_base = 0x170;
      channel->IRQ_NO = 0x20 + 15;
      break;
    }
    channel->expecting_intr = false;
    lock_init(&channel->_lock);
    sema_init(&channel->disk_done, 0);

    register_handler(channel->IRQ_NO, intr_hd_handler);
    while (dev_NO < 2) {
      struct disk *hd = &channel->devices[dev_NO];
      hd->which_channel = channel;
      hd->dev_NO = dev_NO;
      sprintf(hd->name, "sd%c", 'a' + channel_NO * 2 + dev_NO);
      identify_disk(hd);
      if (dev_NO != 0) {
        partition_scan(hd, 0);
      }
      primary_disk_NO = 0;
      logical_disk_NO = 0;
      dev_NO++;
    }
    channel_NO++;
    dev_NO = 0;
  }

  printk("\n all partition info as follows:\n");
  list_traversal(&partition_list, print_partition_info, 0);
  printk("ide_init done\n");
}
