#include "string.h"
#include "assert.h"
#include "global.h"

void memset(void *dst, uint8_t value, uint32_t size) {
  assert(dst != NULL);
  uint8_t *dst_in_byte = (uint8_t *)dst;
  while (size-- > 0)
    *dst_in_byte++ = value;
}

void memcpy(void *dst, const void *src, uint32_t size) {
  assert(dst != NULL && src != NULL);
  uint8_t *dst_in_byte = (uint8_t *)dst;
  const uint8_t *src_in_byte = (uint8_t *)src;
  while (size-- > 0) {
    *dst_in_byte++ = *src_in_byte++;
  }
}


int memcmp(const void *a, const void *b, unsigned long size) {
  assert(a != NULL && b != NULL);
  const char *a_in_char = a;
  const char *b_in_char = b;
  while (size-- > 0) {
    if (*a_in_char != *b_in_char)
      return *a_in_char > *b_in_char ? 1 : -1;
    ++a_in_char;
    ++b_in_char;
  }
  return 0;
}

char *strcpy(char *dst, const char *src) {
  assert(dst != NULL && src != NULL);
  char *ret = dst;
  while ((*dst++ = *src++))
    ;
  return ret;
}


uint32_t strlen(const char *str) {
  assert(str != NULL);
  const char *p = str;
  while (*p++)
    ;
  return p - str - 1;
}

int8_t strcmp(const char *a, const char *b) {
  assert(a != NULL && b != NULL);
  while (*a != 0 && *a == *b) {
    ++a;
    ++b;
  }
  return *a < *b ? -1 : *a > *b;
}

char *strcat(char *dst, const char *src) {
  assert(dst != NULL && src != NULL);

  char *iter_dst = dst;
  while (*iter_dst++)
    ;
  --iter_dst;

  while ((*iter_dst++ = *src++))
    ;
  return dst;
}


char *strchr(const char *str, const uint8_t ch) {
  assert(str != NULL);
  while (*str != 0 && *str != ch)
    ++str;
  return *str == ch ? (char *)str : NULL;
}


char *strrchr(const char *str, int ch) {
  assert(str != NULL);
  const char *last_ch = NULL;
  while (*str != 0) {
    if (*str == ch)
      last_ch = str;
    ++str;
  }
  return (char *)last_ch;
}

uint32_t strchrs(const char *src, uint8_t ch) {
  assert(src != NULL);
  int32_t ch_cnt = 0;
  const char *p = src;
  while (*p != 0) {
    if (*p == ch)
      ch_cnt++;
    p++;
  }
  return ch_cnt;
}
