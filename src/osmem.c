// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE
#include "osmem.h"
#include "block_meta.h"
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALLOC_SIZE 128 * 1024
static struct block_meta *head = NULL;

size_t align8(size_t size) { return (size + 7) & ~7; }

struct block_meta *get_last_block() {
  struct block_meta *iter = head;
  while (iter->next) {
    iter = iter->next;
  }
  return iter;
}

void extend_heap(size_t size) {
  size_t extend_size = ALLOC_SIZE;
  if (size < ALLOC_SIZE)
    extend_size = align8(size) + sizeof(struct block_meta);
  struct block_meta *block = sbrk(extend_size);
  block->size = extend_size - sizeof(struct block_meta);
  block->status = STATUS_FREE;
  block->next = block->prev = NULL;

  if (head == NULL)
    head = block;
  else {
    struct block_meta *last = get_last_block();
    last->next = block;
    block->prev = last;
  }
}

void combine_free_blocks() {
  struct block_meta *iter = head;
  while (iter && iter->next) {
    if (iter->status == STATUS_FREE && iter->next->status == STATUS_FREE) {
      iter->size += iter->next->size + sizeof(struct block_meta);
      iter->next = iter->next->next;
      if (iter->next)
        iter->next->prev = iter;
    } else
      iter = iter->next;
  }
}

void split_block(struct block_meta *block, size_t size) {
  size_t aligned_size = align8(size);
  struct block_meta *new_block =
      (struct block_meta *)((char *)block + sizeof(struct block_meta) +
                            aligned_size);
  new_block->size = block->size - aligned_size - sizeof(struct block_meta);
  new_block->status = STATUS_FREE;
  new_block->next = block->next;
  new_block->prev = block;

  if (new_block->next)
    new_block->next->prev = new_block;

  block->size = aligned_size;
  block->next = new_block;
}

struct block_meta *find_best_block(size_t size) {
  size_t aligned_size = align8(size);
  struct block_meta *iter = head;
  struct block_meta *best_block = NULL;

  while (iter) {
    if (iter->status == STATUS_FREE && iter->size >= aligned_size)
      if (best_block == NULL || iter->size < best_block->size)
        best_block = iter;
    iter = iter->next;
  }
  if (best_block && best_block->size > aligned_size + sizeof(struct block_meta))
    split_block(best_block, aligned_size);
  return best_block;
}

struct block_meta *allocate_large_block(size_t size) {
  size_t aligned_size = align8(size) + sizeof(struct block_meta);
  struct block_meta *block = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  block->size = aligned_size - sizeof(struct block_meta);
  block->status = STATUS_MAPPED;
  block->next = block->prev = NULL;
  return block;
}

struct block_meta *allocate_small_block(size_t size) {
  size_t aligned_size = align8(size);
  if (head == NULL)
    extend_heap(ALLOC_SIZE);
  combine_free_blocks();
  struct block_meta *block = find_best_block(aligned_size);
  if (block == NULL) {
    extend_heap(aligned_size);
    block = get_last_block();
  }
  block->status = STATUS_ALLOC;
  return block;
}

void *os_malloc(size_t size) {
  if (size == 0)
    return NULL;
  struct block_meta *block;
  if (size >= ALLOC_SIZE)
    block = allocate_large_block(size);
  else
    block = allocate_small_block(size);

  if (block != NULL)
    return block + 1;
  return NULL;
}

void os_free(void *ptr) {
  if (ptr == NULL)
    return;
  struct block_meta *block = (struct block_meta *)ptr - 1;
  if (block->status == STATUS_MAPPED) {
    munmap(block, block->size + sizeof(struct block_meta));
  } else {
    block->status = STATUS_FREE;
    combine_free_blocks();
  }
}

void *os_calloc(size_t nmemb, size_t size) {
  size_t total_size = nmemb * size;
  if (nmemb == 0 || size == 0)
    return;
  void *ptr = os_malloc(total_size);
  memset(ptr, 0, total_size);
}

void *os_realloc(void *ptr, size_t size) {
  /* TODO: Implement os_realloc */
  return NULL;
}
