#include "bitmap.h"
#include "debug.h"
#include "interrupt.h"
#include "print.h"
#include "string.h"

void bitmap_init(struct bitmap *btmp) {
  memset(btmp->bits, 0, btmp->bmap_bytes_len);
}

bool bitmap_bit_test(struct bitmap *btmp, uint32_t bit_idx) {
  uint32_t byte_idx = bit_idx / 8;
  uint32_t bit_idx_in_byte = bit_idx % 8;

  return (btmp->bits[byte_idx] & (BITMAP_MASK << bit_idx_in_byte));
}

int bitmap_scan(struct bitmap *btmp, uint32_t cnt) {
  uint32_t byte_idx = 0;
  while ((0xff == btmp->bits[byte_idx]) && (byte_idx < btmp->bmap_bytes_len))
    ++byte_idx;

  ASSERT(byte_idx < btmp->bmap_bytes_len);
  if (byte_idx == btmp->bmap_bytes_len)
    return -1;

  int bit_idx = 0;
  while ((uint8_t)(BITMAP_MASK << bit_idx) & btmp->bits[byte_idx])
    ++bit_idx;

  int free_bit_idx_start = byte_idx * 8 + bit_idx;
  if (cnt == 1)
    return free_bit_idx_start;

  uint32_t bit_remaining = btmp->bmap_bytes_len * 8 - free_bit_idx_start;
  uint32_t next_bit = free_bit_idx_start + 1;
  uint32_t count = 1;

  /* Traverse the bits in the bitmap starting from the bit after
   * free_bit_idx_start and find the sequence  */
  free_bit_idx_start = -1;
  while (bit_remaining-- > 0) {
    if (!bitmap_bit_test(btmp, next_bit)) {
      ++count;
    } else {
      count = 0;
    }
    if (count == cnt) {
      free_bit_idx_start = next_bit - cnt + 1;
      break;
    }
    ++next_bit;
  }
  return free_bit_idx_start;
}

/**
 * bitmap_set - Sets or clears a specific bit in a bitmap.
 * @btmp: A pointer to the bitmap.
 * @bit_idx: The index of the bit to set or clear.
 * @value: The value to set the bit to (0 or 1).
 *
 * Sets the bit at index 'bit_idx' in the bitmap to 'value'.
 */
void bitmap_set(struct bitmap *btmp, uint32_t bit_idx, int8_t value) {
  ASSERT((value == 0) || (value == 1));
  uint32_t byte_idx = bit_idx / 8;
  uint32_t bit_idx_in_byte = bit_idx % 8;

  if (value) {
    btmp->bits[byte_idx] |= BITMAP_MASK << bit_idx_in_byte;
  } else {
    btmp->bits[byte_idx] &= ~(BITMAP_MASK << bit_idx_in_byte);
  }
}
