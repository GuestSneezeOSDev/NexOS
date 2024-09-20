#include "memory.h"
#include "bitmap.h"
#include "debug.h"
#include "global.h"
#include "interrupt.h"
#include "list.h"
#include "print.h"
#include "stdint.h"
#include "string.h"
#include "sync.h"
#include "thread.h"

#define MEM_BITMAP_BASE 0xc009a000

#define KERNEL_HEAP_START 0xc0100000

#define PDE_IDX(addr) ((addr & 0xffc00000) >> 22)
#define PTE_IDX(addr) ((addr & 0x003ff000) >> 12)

struct pool {
  struct bitmap pool_bitmap;
  uint32_t phy_addr_start;
  uint32_t pool_size;
  struct lock _lock;
};

struct pool kernel_pool, user_pool;

struct virtual_addr kernel_vaddr;

struct arena {
  struct mem_block_desc *desc;
  uint32_t cnt;
  bool large_mb;
};

struct mem_block_desc k_mb_desc_arr[MB_DESC_CNT];

static void mem_pool_init(uint32_t all_mem) {
  put_str("  mem_pool_init start\n");
  lock_init(&kernel_pool._lock);
  lock_init(&user_pool._lock);

  uint32_t page_table_size = PAGE_SIZE * 256;

  uint32_t used_mem = page_table_size + 0x100000;
  uint32_t free_mem = all_mem - used_mem;

  uint16_t all_free_pages = free_mem / PAGE_SIZE;

  uint16_t kernel_free_pages = all_free_pages / 2;
  uint16_t user_free_pages = all_free_pages - kernel_free_pages;

  uint32_t kernel_bitmap_len = kernel_free_pages / 8;
  uint32_t user_bitmap_len = user_free_pages / 8;

  uint32_t kernel_pool_start = used_mem;
  uint32_t user_pool_start = kernel_pool_start + kernel_free_pages * PAGE_SIZE;

  kernel_pool.phy_addr_start = kernel_pool_start;
  kernel_pool.pool_size = kernel_free_pages * PAGE_SIZE;
  kernel_pool.pool_bitmap.bmap_bytes_len = kernel_bitmap_len;

  user_pool.phy_addr_start = user_pool_start;
  user_pool.pool_size = user_free_pages * PAGE_SIZE;
  user_pool.pool_bitmap.bmap_bytes_len = user_bitmap_len;

  kernel_pool.pool_bitmap.bits = (void *)MEM_BITMAP_BASE;
  user_pool.pool_bitmap.bits = (void *)(MEM_BITMAP_BASE + kernel_bitmap_len);

  put_str("    kernel_pool_bitmap_start:");
  put_int((int)kernel_pool.pool_bitmap.bits);
  put_str(" kernel_pool_phy_start:");
  put_int(kernel_pool.phy_addr_start);
  put_str("\n");

  put_str("    user_pool_bitmap_start:");
  put_int((int)user_pool.pool_bitmap.bits);
  put_str(" user_pool_phy_start:");
  put_int(user_pool.phy_addr_start);
  put_str("\n");

  bitmap_init(&kernel_pool.pool_bitmap);
  bitmap_init(&user_pool.pool_bitmap);

  kernel_vaddr.vaddr_bitmap.bmap_bytes_len = kernel_bitmap_len;
  kernel_vaddr.vaddr_bitmap.bits =
      (void *)(MEM_BITMAP_BASE + kernel_bitmap_len + user_bitmap_len);

  kernel_vaddr.vaddr_start = KERNEL_HEAP_START;
  bitmap_init(&kernel_vaddr.vaddr_bitmap);
  put_str("  mem_pool_init done\n");
}


void block_desc_init(struct mem_block_desc *k_mb_desc_arr) {
  uint16_t desc_idx, _block_size = 16;
  for (desc_idx = 0; desc_idx < MB_DESC_CNT; desc_idx++) {
    k_mb_desc_arr[desc_idx].block_size = _block_size;
    k_mb_desc_arr[desc_idx].block_per_arena =
        (PAGE_SIZE - sizeof(struct arena)) / _block_size;
    list_init(&k_mb_desc_arr[desc_idx].free_list);
    _block_size *= 2;
  }
}


void mem_init() {
  put_str("mem_init start\n");
  uint32_t mem_bytes_total = (*(uint32_t *)(0xb00));
  mem_pool_init(mem_bytes_total);
  block_desc_init(k_mb_desc_arr);
  put_str("mem_init done\n");
}

static void *vaddr_get(enum pool_flags pf, uint32_t pg_cnt) {
  int vaddr_start = 0, free_bit_idx_start = -1;
  uint32_t cnt = 0;

  if (pf == PF_KERNEL) {
    free_bit_idx_start = bitmap_scan(&kernel_vaddr.vaddr_bitmap, pg_cnt);
    if (free_bit_idx_start == -1)
      return NULL;
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, free_bit_idx_start + cnt++, 1);
    }
    vaddr_start = kernel_vaddr.vaddr_start + free_bit_idx_start * PAGE_SIZE;
  } else {
    struct task_struct *cur = running_thread();
    free_bit_idx_start = bitmap_scan(&cur->userprog_vaddr.vaddr_bitmap, pg_cnt);
    if (free_bit_idx_start == -1)
      return NULL;
    while (cnt < pg_cnt) {
      bitmap_set(&cur->userprog_vaddr.vaddr_bitmap, free_bit_idx_start + cnt++,
                 1);
    }
    vaddr_start =
        cur->userprog_vaddr.vaddr_start + free_bit_idx_start * PAGE_SIZE;
    ASSERT((uint32_t)vaddr_start < (0xc0000000 - PAGE_SIZE));
  }
  return (void *)vaddr_start;
}

uint32_t *pte_ptr(uint32_t vaddr) {
  uint32_t *pte = (uint32_t *)(0xffc00000 + ((vaddr & 0xffc00000) >> 10) +
                               PTE_IDX(vaddr) * 4);
  return pte;
}

uint32_t *pde_ptr(uint32_t vaddr) {
  uint32_t *pde = (uint32_t *)((0xfffff000) + PDE_IDX(vaddr) * 4);
  return pde;
}

static void *palloc(struct pool *m_pool) {
  int bit_idx = bitmap_scan(&m_pool->pool_bitmap, 1);
  if (bit_idx == -1)
    return NULL;
  bitmap_set(&m_pool->pool_bitmap, bit_idx, 1);
  uint32_t page_phy_addr = m_pool->phy_addr_start + bit_idx * PAGE_SIZE;
  return (void *)page_phy_addr;
}

static void page_table_add(void *_vaddr, void *_page_phy_addr) {
  uint32_t vaddr = (uint32_t)_vaddr;
  uint32_t page_phy_addr = (uint32_t)_page_phy_addr;
  uint32_t *pde = pde_ptr(vaddr);
  uint32_t *pte = pte_ptr(vaddr);

  if (*pde & 0x00000001) {
    ASSERT(!(*pte & 0x00000001));

    *pte = (page_phy_addr | PG_US_U | PG_RW_W | PG_P_1);
  } else {
    uint32_t pde_phy_addr = (uint32_t)palloc(&kernel_pool);
    *pde = (pde_phy_addr | PG_US_U | PG_RW_W | PG_P_1);
    memset((void *)((int)pte & 0xfffff000), 0, PAGE_SIZE);

    *pte = (page_phy_addr | PG_US_U | PG_RW_W | PG_P_1);
  }
}

void *malloc_page(enum pool_flags pf, uint32_t pg_cnt) {
  ASSERT(pg_cnt > 0 && pg_cnt < 3840);
  void *vaddr_start = vaddr_get(pf, pg_cnt);
  if (vaddr_start == NULL)
    return NULL;

  uint32_t vaddr = (uint32_t)vaddr_start;
  uint32_t cnt = pg_cnt;
  struct pool *mem_pool = (pf & PF_KERNEL) ? &kernel_pool : &user_pool;

  while (cnt-- > 0) {
    void *page_phy_addr = palloc(mem_pool);
    if (page_phy_addr == NULL)
      return NULL;
    page_table_add((void *)vaddr, page_phy_addr);
    vaddr += PAGE_SIZE;
  }
  return vaddr_start;
}


void *get_kernel_pages(uint32_t pg_cnt) {
  void *vaddr = malloc_page(PF_KERNEL, pg_cnt);
  if (vaddr != NULL)
    memset(vaddr, 0, pg_cnt * PAGE_SIZE);
  return vaddr;
}

void *get_user_page(uint32_t pg_cnt) {
  lock_acquire(&user_pool._lock);
  void *vaddr = malloc_page(PF_USER, pg_cnt);
  if (vaddr != NULL)
    memset(vaddr, 0, pg_cnt * PAGE_SIZE);
  lock_release(&user_pool._lock);
  return vaddr;
}

void *get_a_page(enum pool_flags pf, uint32_t vaddr) {
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
  lock_acquire(&mem_pool->_lock);
  struct task_struct *cur_thread = running_thread();
  int32_t bit_idx = -1;

  if (cur_thread->pg_dir != NULL && pf == PF_USER) {
    bit_idx = (vaddr - cur_thread->userprog_vaddr.vaddr_start) / PAGE_SIZE;
    ASSERT(bit_idx > 0);
    bitmap_set(&cur_thread->userprog_vaddr.vaddr_bitmap, bit_idx, 1);
  } else if (cur_thread->pg_dir == NULL && pf == PF_KERNEL) {
    bit_idx = (vaddr - kernel_vaddr.vaddr_start) / PAGE_SIZE;
    ASSERT(bit_idx > 0);
    bitmap_set(&kernel_vaddr.vaddr_bitmap, bit_idx, 1);
  } else {
    PANIC("Unable to establish mapping between pf and vaddr");
  }
  void *page_phy_addr = palloc(mem_pool);
  if (page_phy_addr == NULL) {
    lock_release(&mem_pool->_lock);
    return NULL;
  }
  page_table_add((void *)vaddr, page_phy_addr);
  lock_release(&mem_pool->_lock);
  return (void *)vaddr;
}

uint32_t addr_v2p(uint32_t vaddr) {
  uint32_t *pte_phy_addr = pte_ptr(vaddr);
  return ((*pte_phy_addr & 0xfffff000) + (vaddr & 0x00000fff));
}

static struct mem_block *arena_2_block(struct arena *a, uint32_t idx) {
  return (struct mem_block *)((uint32_t)a + sizeof(struct arena) +
                              idx * a->desc->block_size);
}

static struct arena *block_2_arena(struct mem_block *mb) {
  return (struct arena *)((uint32_t)mb & 0xfffff000);
}

void *sys_malloc(uint32_t _size) {
  enum pool_flags PF;
  struct pool *mem_pool;
  uint32_t pool_size;
  struct mem_block_desc *desc;
  struct task_struct *cur_thread = running_thread();

  if (cur_thread->pg_dir == NULL) {
    PF = PF_KERNEL;
    pool_size = kernel_pool.pool_size;
    mem_pool = &kernel_pool;
    desc = k_mb_desc_arr;
  } else {
    PF = PF_USER;
    pool_size = user_pool.pool_size;
    mem_pool = &user_pool;
    desc = cur_thread->u_mb_desc_arr;
  }

  if (!(_size < pool_size))
    return NULL;

  struct arena *a = NULL;
  struct mem_block *b = NULL;
  lock_acquire(&mem_pool->_lock);

  if (_size > 1024) {
    uint32_t pg_cnt = DIV_ROUND_UP(_size + sizeof(struct arena), PAGE_SIZE);
    a = malloc_page(PF, pg_cnt);
    if (a != NULL) {
      memset(a, 0, pg_cnt * PAGE_SIZE);
      a->desc = NULL;
      a->cnt = pg_cnt;
      a->large_mb = true;
      lock_release(&mem_pool->_lock);
      return (void *)(a + 1);
    } else {
      lock_release(&mem_pool->_lock);
      return NULL;
    }
  } else {
    uint8_t desc_idx;
    for (desc_idx = 0; desc_idx < MB_DESC_CNT; desc_idx++) {
      if (_size <= desc[desc_idx].block_size)
        break;
    }

    if (list_empty(&desc[desc_idx].free_list)) {
      a = malloc_page(PF, 1);
      if (a == NULL) {
        lock_release(&mem_pool->_lock);
        return NULL;
      }
      memset(a, 0, PAGE_SIZE);
      a->desc = &desc[desc_idx];
      a->large_mb = false;
      a->cnt = desc[desc_idx].block_per_arena;

      uint32_t block_idx;
      enum intr_status old_status = intr_disable();
      for (block_idx = 0; block_idx < a->desc->block_per_arena; block_idx++) {
        b = arena_2_block(a, block_idx);
        ASSERT(!list_elem_find(&a->desc->free_list, &b->free_elem));
        list_append(&a->desc->free_list, &b->free_elem);
      }
      intr_set_status(old_status);
    }
    b = elem2entry(struct mem_block, free_elem,
                   list_pop(&desc[desc_idx].free_list));
    memset(b, 0, desc[desc_idx].block_size);
    a = block_2_arena(b);
    --a->cnt;
    lock_release(&mem_pool->_lock);
    return (void *)b;
  }
}

void pfree(uint32_t page_phy_addr) {
  struct pool *mem_pool;
  uint32_t bit_idx = 0;
  mem_pool =
      (page_phy_addr >= user_pool.phy_addr_start) ? &user_pool : &kernel_pool;
  bit_idx = (page_phy_addr - mem_pool->phy_addr_start) / PAGE_SIZE;
  bitmap_set(&mem_pool->pool_bitmap, bit_idx, 0);
}

static void page_table_pte_remove(uint32_t vaddr) {
  uint32_t *pte = pte_ptr(vaddr);
  *pte &= PG_P_0;
  asm volatile("invlpg %0" ::"m"(vaddr) : "memory");
}

static void vaddr_remove(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
  uint32_t allocated_bit_idx_start = -1;
  uint32_t vaddr = (uint32_t)_vaddr;
  uint32_t cnt = 0;
  if (pf == PF_KERNEL) {
    allocated_bit_idx_start = (vaddr - kernel_vaddr.vaddr_start) / PAGE_SIZE;
    while (cnt < pg_cnt) {
      bitmap_set(&kernel_vaddr.vaddr_bitmap, allocated_bit_idx_start + cnt++,
                 0);
    }
  } else {
    struct task_struct *cur_thread = running_thread();
    allocated_bit_idx_start =
        (vaddr - cur_thread->userprog_vaddr.vaddr_start) / PAGE_SIZE;
    while (cnt < pg_cnt) {
      bitmap_set(&cur_thread->userprog_vaddr.vaddr_bitmap,
                 allocated_bit_idx_start + cnt++, 0);
    }
  }
}

void mfree_page(enum pool_flags pf, void *_vaddr, uint32_t pg_cnt) {
  uint32_t vaddr = (uint32_t)_vaddr;
  uint32_t cnt = 0;
  ASSERT(pg_cnt >= 1 && vaddr % PAGE_SIZE == 0);
  uint32_t page_phy_addr = addr_v2p(vaddr);

  ASSERT((page_phy_addr % PAGE_SIZE) == 0 && page_phy_addr >= 0x102000);

  if (page_phy_addr >= user_pool.phy_addr_start) {
    while (cnt < pg_cnt) {
      page_phy_addr = addr_v2p(vaddr);
      ASSERT((page_phy_addr % PAGE_SIZE) == 0 &&
             page_phy_addr >= user_pool.phy_addr_start);
      pfree(page_phy_addr);
      page_table_pte_remove(vaddr);
      vaddr += PAGE_SIZE;

      cnt++;
    }
  } else {
    while (cnt < pg_cnt) {
      page_phy_addr = addr_v2p(vaddr);
      ASSERT((page_phy_addr % PAGE_SIZE) == 0 &&
             page_phy_addr >= kernel_pool.phy_addr_start &&
             page_phy_addr < user_pool.phy_addr_start);

      pfree(page_phy_addr);
      page_table_pte_remove(vaddr);
      vaddr += PAGE_SIZE;

      cnt++;
    }
  }
  vaddr_remove(pf, _vaddr, pg_cnt);
}

void sys_free(void *ptr) {
  ASSERT(ptr != NULL);
  if (ptr == NULL)
    return;
  enum pool_flags pf;
  struct pool *mem_pool;

  if (running_thread()->pg_dir == NULL) {
    ASSERT((uint32_t)ptr >= KERNEL_HEAP_START);
    pf = PF_KERNEL;
    mem_pool = &kernel_pool;
  } else {
    pf = PF_USER;
    mem_pool = &user_pool;
  }
  lock_acquire(&mem_pool->_lock);

  struct mem_block *b = ptr;
  struct arena *a = block_2_arena(b);
  if (a->desc == NULL && a->large_mb == true) {
    mfree_page(pf, a, a->cnt);
  } else {
    list_append(&a->desc->free_list, &b->free_elem);

    if (++a->cnt == a->desc->block_per_arena) {
      uint32_t block_idx;
      for (block_idx = 0; block_idx < a->desc->block_per_arena; block_idx++) {
        struct mem_block *b = arena_2_block(a, block_idx);
        ASSERT(list_elem_find(&a->desc->free_list, &b->free_elem));
        list_remove(&b->free_elem);
      }
      mfree_page(pf, a, 1);
    }
  }
  lock_release(&mem_pool->_lock);
}

void *get_page_to_vaddr_without_bitmap(enum pool_flags pf, uint32_t vaddr) {
  struct pool *mem_pool = pf & PF_KERNEL ? &kernel_pool : &user_pool;
  lock_acquire(&mem_pool->_lock);

  void *page_phy_addr = palloc(mem_pool);
  if (page_phy_addr == NULL) {
    lock_release(&mem_pool->_lock);
    return NULL;
  }
  page_table_add((void *)vaddr, page_phy_addr);
  lock_release(&mem_pool->_lock);
  return (void *)vaddr;
}
