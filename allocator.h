#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_
#include <stddef.h>
#include <stdint.h>

#define MM_ALIGNMENT 40u

#ifndef UNUSED_PATTERN_BYTES
#define UNUSED_PATTERN_BYTES {0xA5u, 0x5Au, 0x3Cu, 0xC3u, 0x7Eu}
#endif

int mm_init(uint8_t *heap, size_t heap_size);
void *mm_malloc(size_t size);
int mm_read(void *ptr, size_t offset, void *buf, size_t len);
int mm_write(void *ptr, size_t offset, const void *src, size_t len);
void mm_free(void *ptr);
void *mm_realloc(void *ptr, size_t new_size);

void mm_heap_stats(void);

void mm_heap_dump(int verbose);

#endif
