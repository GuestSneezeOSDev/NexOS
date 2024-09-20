#include "keyboard.h"
#include "global.h"
#include "interrupt.h"
#include "io.h"
#include "io_queue.h"
#include "print.h"
#include "stdint.h"

#define KBD_BUF_PORT 0x60

#define esc '\033'
#define backspace '\b'
#define tab '\t'
#define enter '\r'
#define delete '\177'

#define char_invisible 0
#define left_ctrl char_invisible
#define right_ctrl char_invisible
#define left_shift char_invisible
#define right_shift char_invisible
#define left_alt char_invisible
#define right_alt char_invisible
#define caps_lock char_invisible

#define l_shift_makecode 0x2a
#define r_shift_makecode 0x36
#define l_alt_makecode 0x38
#define r_alt_makecode 0xe038
#define r_alt_breakcode 0xe0b8
#define l_ctrl_makecode 0x1d
#define r_ctrl_makecode 0xe01d
#define r_ctrl_breakcode 0xe09d
#define caps_lock_makecode 0x3a

static bool ctrl_status, shift_status, alt_status, caps_lock_status;
static bool extend_scancode;
struct ioqueue kbd_circular_buf;

static char keymap[][2] = {{0, 0},
                           {esc, esc},
                           {'1', '!'},
                           {'2', '@'},
                           {'3', '#'},
                           {'4', '$'},
                           {'5', '%'},
                           {'6', '^'},
                           {'7', '&'},
                           {'8', '*'},
                           {'9', '('},
                           {'0', ')'},
                           {'-', '_'},
                           {'=', '+'},
                           {backspace, backspace},
                           {tab, tab},
                           {'q', 'Q'},
                           {'w', 'W'},
                           {'e', 'E'},
                           {'r', 'R'},
                           {'t', 'T'},
                           {'y', 'Y'},
                           {'u', 'U'},
                           {'i', 'I'},
                           {'o', 'O'},
                           {'p', 'P'},
                           {'[', '{'},
                           {']', '}'},
                           {enter, enter},
                           {left_ctrl, left_ctrl},
                           {'a', 'A'},
                           {'s', 'S'},
                           {'d', 'D'},
                           {'f', 'F'},
                           {'g', 'G'},
                           {'h', 'H'},
                           {'j', 'J'},
                           {'k', 'K'},
                           {'l', 'L'},
                           {';', ':'},
                           {',', '"'},
                           {'`', '~'},
                           {left_shift, left_shift},
                           {'\\', '|'},
                           {'z', 'Z'},
                           {'x', 'X'},
                           {'c', 'C'},
                           {'v', 'V'},
                           {'b', 'B'},
                           {'n', 'N'},
                           {'m', 'M'},
                           {',', '<'},
                           {'.', '>'},
                           {'/', '?'},
                           {right_shift, right_shift},
                           {'*', '*'},
                           {left_alt, left_alt},
                           {' ', ' '},
                           {caps_lock, caps_lock}};

static void intr_keyboard_handler(void) {
  bool ctrl_down_last = ctrl_status;
  bool shift_down_last = shift_status;
  bool caps_lock_last = caps_lock_status;
  bool break_code;

  uint16_t scancode = inb(KBD_BUF_PORT);

  if (scancode == 0xe0) {
    extend_scancode = true;
    return;
  }
  if (extend_scancode) {
    scancode = (0xe0 << 2) | scancode;
    extend_scancode = false;
  }

  break_code = ((scancode & (0x01 << 7)) != 0);

  if (break_code) {
    uint16_t makecode = scancode & (0xffff ^ (0x01 << 7));

    if (makecode == l_ctrl_makecode || makecode == r_ctrl_makecode)
      ctrl_status = false;
    if (makecode == l_shift_makecode || makecode == r_shift_makecode)
      shift_status = false;
    if (makecode == l_alt_makecode || makecode == r_alt_makecode)
      alt_status = false;
    return;
  } else if (scancode < 0x3b || scancode == right_ctrl ||
             scancode == right_alt) {
    bool shift = false;

    if ((scancode < 0x0e) || (scancode == 0x29) || (scancode == 0x1a) ||
        (scancode == 0x1b) || (scancode == 0x2b) || (scancode == 0x27) ||
        (scancode == 0x28) || (scancode == 0x33) || (scancode == 0x34) ||
        (scancode == 0x35)) {
      if (shift_down_last)
        shift = true;
    } else {
      if (shift_down_last && caps_lock_last) {
        shift = false;
      } else if (shift_down_last || caps_lock_last) {
        shift = true;
      } else {
        shift = false;
      }
    }

    uint8_t index = scancode & 0x00ff;

    char cur_char = keymap[index][shift];
    if ((ctrl_down_last && cur_char == 'l') ||
        (ctrl_down_last && cur_char == 'u')) {
      cur_char -= 'a';
    }

    if (cur_char) {
      if (!ioq_is_full(&kbd_circular_buf)) {
        ioq_putchar(&kbd_circular_buf, cur_char);
      }
      return;
    }

    if (scancode == l_ctrl_makecode || scancode == r_ctrl_makecode) {
      ctrl_status = true;
    } else if (scancode == l_shift_makecode || scancode == r_shift_makecode) {
      shift_status = true;
    } else if (scancode == l_alt_makecode || scancode == r_alt_makecode) {
      alt_status = true;
    } else if (scancode == caps_lock_makecode) {
      caps_lock_status = !caps_lock_status;
    }
  } else {
    put_str("unknown key\n");
  }
}

void keyboard_init() {
  put_str("keyboard init start\n");
  ioqueue_init(&kbd_circular_buf);
  register_handler(0x21, intr_keyboard_handler);
  put_str("keyboard init done\n");
}
