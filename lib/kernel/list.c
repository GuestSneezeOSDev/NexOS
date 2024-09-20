#include "list.h"
#include "interrupt.h"

void list_init(struct list *plist) {
  plist->head.prev = NULL;
  plist->head.next = &plist->tail;
  plist->tail.next = NULL;
  plist->tail.prev = &plist->head;
}

void list_insert_before(struct list_elem *posn, struct list_elem *elem) {
  enum intr_status old_status = intr_disable();

  elem->next = posn;
  elem->prev = posn->prev;
  posn->prev->next = elem;
  posn->prev = elem;

  intr_set_status(old_status);
}

void list_push(struct list *plist, struct list_elem *elem) {
  list_insert_before(plist->head.next, elem);
}

void list_append(struct list *plist, struct list_elem *elem) {
  list_insert_before(&plist->tail, elem);
}

void list_remove(struct list_elem *elem) {
  enum intr_status old_status = intr_disable();

  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;

  intr_set_status(old_status);
}

struct list_elem *list_pop(struct list *plist) {
  struct list_elem *elem = plist->head.next;
  list_remove(elem);
  return elem;
}

bool list_elem_find(struct list *plist, struct list_elem *obj_elem) {
  struct list_elem *iter = plist->head.next;
  while (iter != &plist->tail) {
    if (iter == obj_elem)
      return true;
    iter = iter->next;
  }
  return false;
}

bool list_empty(struct list *plist) { return plist->head.next == &plist->tail; }

struct list_elem *list_traversal(struct list *plist, function func, int arg) {
  if (list_empty(plist))
    return NULL;

  struct list_elem *iter = plist->head.next;
  while (iter != &plist->tail) {
    if (func(iter, arg))
      return iter;
    iter = iter->next;
  }
  return NULL;
}

uint32_t list_len(struct list *plist) {
  uint32_t len = 0;
  struct list_elem *iter = plist->head.next;
  while (iter != &plist->tail) {
    ++len;
    iter = iter->next;
  }
  return len;
}
