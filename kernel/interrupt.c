#include "interrupt.h"
#include "global.h"
#include "io.h"
#include "print.h"
#include "stdint.h"

#define PIC_M_CTRL 0x20
#define PIC_M_DATA 0x21
#define PIC_S_CTRL 0xa0
#define PIC_S_DATA 0xa1

#define IDT_DESC_COUNT 0x81

#define EFLAGS_IF 0x00000200
#define GET_EFLAGS(EFLAGS_VAR) asm volatile("pushfl;popl %0" : "=g"(EFLAGS_VAR))

struct gate_desc {
  uint16_t func_offset_low_word;
  uint16_t selector;

  uint8_t dcount;
  uint8_t attribute;
  uint16_t func_offset_high_word;
};

static struct gate_desc idt[IDT_DESC_COUNT];

char *intr_name[IDT_DESC_COUNT];

intr_handler idt_table[IDT_DESC_COUNT];

extern intr_handler intr_entry_table[IDT_DESC_COUNT];
extern uint32_t syscall_handler(void);

static void pic_init() {
  outb(PIC_M_CTRL, 0x11);
  outb(PIC_M_DATA, 0x20);
  outb(PIC_M_DATA, 0x04);
  outb(PIC_M_DATA, 0x01);

  outb(PIC_S_CTRL, 0x11);
  outb(PIC_S_DATA, 0x28);
  outb(PIC_S_DATA, 0x02);
  outb(PIC_S_DATA, 0x01);

  outb(PIC_M_DATA, 0xf8);
  outb(PIC_S_DATA, 0xbf);

  put_str("  pic_init done\n");
}

static void make_idt_desc(struct gate_desc *pt_gdesc, uint8_t attr,
                          intr_handler function) {
  pt_gdesc->func_offset_low_word = (uint32_t)function & 0x0000FFFF;
  pt_gdesc->selector = SELECTOR_KERNEL_CODE;
  pt_gdesc->dcount = 0;
  pt_gdesc->attribute = attr;
  pt_gdesc->func_offset_high_word = ((uint32_t)function & 0xFFFF0000) >> 16;
}

static void idt_desc_init() {
  int i;
  for (i = 0; i < IDT_DESC_COUNT; ++i) {
    make_idt_desc(&idt[i], IDT_DESC_ATTR_DPL0, intr_entry_table[i]);
  }

  int lastindex = IDT_DESC_COUNT - 1;
  make_idt_desc(&idt[lastindex], IDT_DESC_ATTR_DPL3, syscall_handler);
  put_str("  idt_desc_init done\n");
}

static void general_intr_handler(uint8_t vec_nr) {
  if (vec_nr == 0x27 || vec_nr == 0x2f)
    return;

  set_cursor(0);
  int cursor_pos = 0;
  while (cursor_pos < 320) {
    put_char(' ');
    ++cursor_pos;
  }
  set_cursor(0);
  put_str("!!!!!!      exception message begin      !!!!!!\n");
  set_cursor(88);
  put_str(intr_name[vec_nr]);
  if (vec_nr == 14) {
    uint32_t page_fault_vaddr;
    asm volatile("movl %%cr2,%0" : "=r"(page_fault_vaddr));
    put_str("\npage fault addr is ");
    put_int(page_fault_vaddr);
  }
  put_str("\n!!!!!!      exception message end      !!!!!!\n");
  while (1)
    ;
}

void register_handler(uint8_t vec_nr, intr_handler function) {
  idt_table[vec_nr] = function;
}

static void exception_init() {
  int i;
  for (i = 0; i < IDT_DESC_COUNT; ++i) {
    idt_table[i] = general_intr_handler;
    intr_name[i] = "unknown";
  }

  intr_name[0] = "#DE Divide Error";
  intr_name[1] = "#DB Debug";
  intr_name[2] = "NMI Interrupt";
  intr_name[3] = "#BP BreakPoint";
  intr_name[4] = "#OF Overflow";
  intr_name[5] = "#BR BOUND Range Exceeded";
  intr_name[6] = "#UD Undefined Opcode";
  intr_name[7] = "#NM Device Not Available";
  intr_name[8] = "#DF Double Fault";
  intr_name[9] = "#MF CoProcessor Segment Overrun";
  intr_name[10] = "#TS Invalid TSS";
  intr_name[11] = "#NP Segment Not Present";
  intr_name[12] = "#SS Stack Segment Fault";
  intr_name[13] = "#GP General  Protection";
  intr_name[14] = "#PF Page Fault";
  intr_name[16] = "#MF x87 FPU Floating-Point Error";
  intr_name[17] = "#AC Alignment Check";
  intr_name[18] = "#MC Machine Check";
  intr_name[19] = "#XM SIMD Floating-Point Exception";
  intr_name[20] = "Clock Interrupt";
  intr_name[21] = "Keyboard Interrupt";
}

void idt_init() {
  put_str("idt_init start\n");

  idt_desc_init();
  exception_init();
  pic_init();

  uint64_t idt_operand = ((sizeof(idt) - 1) | ((uint64_t)(uint32_t)idt << 16));
  asm volatile("lidt %0" ::"m"(idt_operand));

  put_str("idt_init done\n");
}

enum intr_status intr_get_status() {
  uint32_t eflags = 0;
  GET_EFLAGS(eflags);
  return (EFLAGS_IF & eflags) ? INTR_ON : INTR_OFF;
}

enum intr_status intr_enable() {
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
    old_status = INTR_ON;
  } else {
    old_status = INTR_OFF;
    asm volatile("sti");
  }
  return old_status;
}

enum intr_status intr_disable() {
  enum intr_status old_status;
  if (INTR_ON == intr_get_status()) {
    old_status = INTR_ON;
    asm volatile("cli" : : : "memory");
  } else {
    old_status = INTR_OFF;
  }
  return old_status;
}
enum intr_status intr_set_status(enum intr_status status) {
  return status & INTR_ON ? intr_enable() : intr_disable();
}
