#include "stdio.h"
#include "global.h"
#include "stdint.h"
#include "string.h"
#include "syscall.h"

static void itoa(uint32_t value, char **buf_ptr_addr, uint8_t base) {
  uint32_t m = value % base;
  uint32_t i = value / base;
  if (i) {
    itoa(i, buf_ptr_addr, base);
  }
  if (m < 10) {
    *((*buf_ptr_addr)++) = m + '0';
  } else {
    *((*buf_ptr_addr)++) = m - 10 + 'A';
  }
}

uint32_t vsprintf(char *str, const char *format, va_list ap) {
  char *buf_ptr = str;
  const char *iter = format;
  char ch = *iter;
  int32_t arg_int;
  char *arg_str;
  while (ch) {
    if (ch != '%') {
      *(buf_ptr++) = ch;
      ch = *(++iter);
      continue;
    }
    ch = *(++iter);
    switch (ch) {
      case 'x':
        arg_int = va_arg(ap, int);
        itoa(arg_int, &buf_ptr, 16);
        ch = *(++iter);
        break;
      case 'c':
        *(buf_ptr++) = va_arg(ap, char);
        ch = *(++iter);
        break;
      case 'd':
        arg_int = va_arg(ap, int);
        if (arg_int < 0) {
          arg_int = 0 - arg_int;
          *(buf_ptr++) = '-';
        }
        itoa(arg_int, &buf_ptr, 10);
        ch = *(++iter);
        break;
      case 's':
        arg_str = va_arg(ap, char *);
        strcpy(buf_ptr, arg_str);
        buf_ptr += strlen(arg_str);
        ch = *(++iter);
        break;
    }
  }
  return strlen(str);
}


uint32_t sprintf(char *buf, const char *format, ...) {
  va_list args;
  uint32_t ret_val;
  va_start(args, format);
  ret_val = vsprintf(buf, format, args);
  va_end(args);
  return ret_val;
}

uint32_t printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  char buf[1024] = {0};
  vsprintf(buf, format, args);
  va_end(args);
  return write(1, buf, strlen(buf));
}
