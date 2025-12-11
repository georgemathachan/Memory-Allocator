// George Mathachan

#include "allocator.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

#define BLOCK_MAGIC        0x12345678u
#define FOOTER_MAGIC       0x87654321u
#define HEADER_SIZE        40u
#define FOOTER_SIZE        16u
#define MIN_PAYLOAD        16u
#define FLAG_ALLOCATED     0x1u
#define FLAG_QUARANTINED   0x2u

#define PAYLOAD_HASH_INIT   0xAAAAAAAAu
#define PAYLOAD_HASH_PRIME  0xBBBBBBBBu
#define HEADER_HASH_SEED    0xCCCCCCCCu
#define HEADER_HASH_PRIME   0xDDDDDDDDu
#define FOOTER_HASH_SEED    0xEEEEEEEEu

#ifndef UNUSED_PATTERN_BYTES
#define UNUSED_PATTERN_BYTES {0xA5u, 0x5Au, 0x3Cu, 0xC3u, 0x7Eu}
#endif

typedef struct __attribute__((packed)) BlockHeader {
    uint32_t magic;
    uint32_t size;
    uint32_t inv_size;
    uint8_t  flags;
    uint8_t  _pad1;
    uint8_t  _pad2;
    uint8_t  _pad3;
    uint64_t integrity_check_value;
    uint32_t size_xor_magic;
    uint32_t client_size_request;
    uint32_t canary;
    uint32_t checksum;
} BlockHeader;

_Static_assert(sizeof(BlockHeader) == HEADER_SIZE,
               "Header must be exactly 40 bytes");

typedef struct __attribute__((packed)) BlockFooter {
    uint32_t magic;
    uint32_t size;
    uint32_t inv_size;
    uint32_t checksum;
} BlockFooter;

_Static_assert(sizeof(BlockFooter) == FOOTER_SIZE,
               "Footer must be exactly 16 bytes");

static uint8_t *g_heap = NULL;
static uint8_t *g_heap_base = NULL;
static size_t g_heap_size = 0;
static bool g_ready = false;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCK()   pthread_mutex_lock(&g_lock)
#define UNLOCK() pthread_mutex_unlock(&g_lock)

static uint8_t g_unused_pattern[5] = UNUSED_PATTERN_BYTES;
static size_t g_pattern_phase = 0;
static bool g_dbg_brown = false;

#define DBG_BROWN(...) \
    do { \
        if (g_dbg_brown) { \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)

static inline size_t align_up(size_t v, size_t align) {
    if (align == 0) return v;
    size_t rem = v % align;
    return rem ? v + (align - rem) : v;
}

static inline size_t align_down(size_t v, size_t align) {
    if (align == 0) return v;
    return v - (v % align);
}

static inline bool in_heap(size_t off, size_t len) {
    return off <= g_heap_size && len <= g_heap_size &&
           off + len <= g_heap_size;
}

static void detect_unused_pattern(const uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < 5) return;

    uint8_t candidate[5];
    for (size_t i = 0; i < 5; ++i) candidate[i] = heap[i];

    size_t sample = heap_size < 25 ? heap_size : 25;
    for (size_t i = 0; i < sample; ++i) {
        if (heap[i] != candidate[i % 5]) return;
    }

    for (size_t i = 0; i < 5; ++i) g_unused_pattern[i] = candidate[i];
}

static bool payload_bounds(size_t off, uint32_t size,
                           size_t *payload_off, size_t *payload_size) {
    if (size < HEADER_SIZE + FOOTER_SIZE) return false;
    size_t poff = off + HEADER_SIZE;
    size_t psz = (size_t)size - HEADER_SIZE - FOOTER_SIZE;
    if (!in_heap(poff, psz)) return false;
    if (payload_off) *payload_off = poff;
    if (payload_size) *payload_size = psz;
    return true;
}

static uint64_t calculate_data_fingerprint(size_t off, uint32_t size) {
    size_t poff = 0, psz = 0;
    if (!payload_bounds(off, size, &poff, &psz)) return 0;

    const uint8_t *p = g_heap + poff;
    uint64_t h = PAYLOAD_HASH_INIT;
    for (size_t i = 0; i < psz; ++i) {
        h ^= p[i];
        h *= PAYLOAD_HASH_PRIME;
    }
    return h;
}

typedef enum { BLOCK_OK = 0, BLOCK_CORRUPT = 1, BLOCK_FATAL = 2 } block_check_t;
static bool block_is_free(const BlockHeader *h);
static bool block_is_quarantined(const BlockHeader *h);

static uint32_t compute_integrity_key(size_t offset, uint32_t size) {
    uint32_t v = (uint32_t)offset ^ (size >> 3) ^ BLOCK_MAGIC;
    v ^= (v >> 13);
    v ^= (v << 5);
    return v;
}

static uint32_t verify_metadata_hash(const BlockHeader *h) {
    const uint8_t *bytes = (const uint8_t *)h;
    uint32_t hash = HEADER_HASH_SEED;
    for (size_t i = 0; i < HEADER_SIZE - sizeof(uint32_t); ++i) {
        hash ^= bytes[i];
        hash *= HEADER_HASH_PRIME;
    }
    hash ^= 0x9E3779B1u;
    return hash;
}

static uint32_t checksum_footer(uint32_t size, uint32_t inv_size) {
    uint32_t hash = FOOTER_HASH_SEED;
    hash ^= size + 0x517CC1B5u + (hash << 7) + (hash >> 3);
    hash ^= inv_size + 0xA2F7CA6Du + (hash << 7) + (hash >> 3);
    hash ^= 0x5DEECE66Du;
    return hash;
}

static BlockHeader *get_block_header(size_t off) {
    if (!in_heap(off, HEADER_SIZE)) return NULL;
    return (BlockHeader *)(g_heap + off);
}

static BlockFooter *ftr_at(size_t off, uint32_t size) {
    if (size < HEADER_SIZE + FOOTER_SIZE) return NULL;
    size_t foff = off + size - FOOTER_SIZE;
    if (!in_heap(foff, FOOTER_SIZE)) return NULL;
    return (BlockFooter *)(g_heap + foff);
}

static void write_header(size_t off, uint32_t size, uint32_t status) {
    BlockHeader *h = get_block_header(off);
    if (!h) return;
    h->magic = BLOCK_MAGIC;
    h->size = size;
    h->inv_size = ~size;
    h->flags = (uint8_t)status;
    h->_pad1 = 0;
    h->_pad2 = 0;
    h->_pad3 = 0;
    h->size_xor_magic = size ^ BLOCK_MAGIC;
    h->canary = compute_integrity_key(off, size);
    h->checksum = verify_metadata_hash(h);
}

static void write_footer(size_t off, uint32_t size) {
    BlockFooter *f = ftr_at(off, size);
    if (!f) return;
    f->magic = FOOTER_MAGIC;
    f->size = size;
    f->inv_size = ~size;
    f->checksum = checksum_footer(size, ~size);
}

static void set_header_extras(size_t off, uint64_t hash, uint64_t aux) {
    BlockHeader *h = get_block_header(off);
    if (!h) return;
    h->integrity_check_value = hash;
    h->client_size_request = aux;
    h->checksum = verify_metadata_hash(h);
}

static void paint_free_payload(size_t off, uint32_t size) {
    size_t payload_off = off + HEADER_SIZE;
    size_t payload_size = 0;
    if (size >= HEADER_SIZE + FOOTER_SIZE)
        payload_size = size - HEADER_SIZE - FOOTER_SIZE;
    if (!in_heap(payload_off, payload_size)) return;

    size_t phase = (payload_off + g_pattern_phase) % 5;
    for (size_t i = 0; i < payload_size; ++i)
        g_heap[payload_off + i] = g_unused_pattern[(phase + i) % 5];
}

static void build_block(size_t off,
    uint32_t size,
    uint32_t status,
    uint64_t requested_size) {
    write_header(off, size, status);
    write_footer(off, size);

    if (status & FLAG_ALLOCATED) {
        set_header_extras(off, calculate_data_fingerprint(off, size),
                          requested_size);
    } else {
        paint_free_payload(off, size);
        set_header_extras(off, calculate_data_fingerprint(off, size), 0);
    }
}

static size_t quarantine_span(size_t off, uint32_t hint_size) {
    size_t max_size = align_down(g_heap_size - off, MM_ALIGNMENT);
    if (max_size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) return 0;

    size_t span = align_up(hint_size ? hint_size : MM_ALIGNMENT,
                           MM_ALIGNMENT);
    if (span < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
        span = HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD;
    if (span > max_size) span = max_size;
    if (span > UINT32_MAX) span = UINT32_MAX;

    build_block(off, (uint32_t)span, FLAG_QUARANTINED, 0);
    return span;
}

static bool recover_header_from_footer(size_t off) {
    size_t start = off + HEADER_SIZE + MIN_PAYLOAD;
    if (start + FOOTER_SIZE > g_heap_size) return false;

    DBG_BROWN("[brown] recover start off=%zu start=%zu\n", off, start);

    for (size_t foff = start; foff + FOOTER_SIZE <= g_heap_size; foff += 1) {
        BlockFooter *f = (BlockFooter *)(g_heap + foff);

        uint32_t size = f->size;
        if (f->magic != FOOTER_MAGIC) continue;
        if (f->inv_size != ~size) continue;
        if (checksum_footer(size, ~size) != f->checksum) continue;
        if (size % MM_ALIGNMENT != 0) continue;
        if (size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) continue;
        if (!in_heap(off, size)) continue;
        if (foff != off + size - FOOTER_SIZE) continue;

        DBG_BROWN("[brown] recover hit footer off=%zu size=%u\n",
                  foff,
                  size);
        write_header(off, size, FLAG_ALLOCATED);
        set_header_extras(off, calculate_data_fingerprint(off, size), 0);
        return true;
    }

    DBG_BROWN("[brown] recover failed off=%zu\n", off);
    return false;
}

static block_check_t validate_block(size_t off, BlockHeader **out_h) {
    BlockHeader *h = get_block_header(off);
    if (!h) return BLOCK_FATAL;
    uint32_t size = h->size;

restart:
    if (h->magic != BLOCK_MAGIC || h->inv_size != ~size ||
        size % MM_ALIGNMENT != 0 ||
        size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD ||
        !in_heap(off, size) ||
        h->size_xor_magic != (size ^ BLOCK_MAGIC)) {
        DBG_BROWN("[brown] invalid header off=%zu magic=0x%x size=%u\n",
                  off,
                  h ? h->magic : 0,
                  h ? h->size : 0);
        if (recover_header_from_footer(off)) {
            h = get_block_header(off);
            if (!h) return BLOCK_FATAL;
            size = h->size;
            goto restart;
        }

        if (h->magic != BLOCK_MAGIC)
            return BLOCK_FATAL;
        return BLOCK_CORRUPT;
    }

    if (h->canary != compute_integrity_key(off, size)) {
        DBG_BROWN("[brown] canary mismatch off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (h->checksum != verify_metadata_hash(h)) {
        DBG_BROWN("[brown] header checksum bad off=%zu size=%u\n",
                  off,
                  size);
        return BLOCK_CORRUPT;
    }

    BlockFooter *f = ftr_at(off, size);
    if (!f) return BLOCK_CORRUPT;
    if (f->magic != FOOTER_MAGIC) {
        DBG_BROWN("[brown] footer magic bad off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (f->size != size || f->inv_size != ~size) {
        DBG_BROWN("[brown] footer size bad off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (f->checksum != checksum_footer(size, ~size)) {
        DBG_BROWN("[brown] footer checksum bad off=%zu size=%u\n",
                  off,
                  size);
        return BLOCK_CORRUPT;
    }

    uint64_t expected = h->integrity_check_value;
    uint64_t actual = calculate_data_fingerprint(off, size);
    if (block_is_quarantined(h)) {
        if (expected != actual) {
            DBG_BROWN("[brown] quarant hash mismatch off=%zu size=%u\n",
                      off,
                      size);
            return BLOCK_CORRUPT;
        }
    } else if (block_is_free(h)) {
        if (expected != actual) {
            DBG_BROWN("[brown] free hash repaint off=%zu size=%u\n",
                      off,
                      size);
            paint_free_payload(off, size);
            set_header_extras(off, calculate_data_fingerprint(off, size),
                              h->client_size_request);
        }
    }

    if (out_h) *out_h = h;
    return BLOCK_OK;
}

static void quarantine_block(size_t off, uint32_t size) {
    BlockHeader *h = get_block_header(off);
    if (!h || !in_heap(off, size)) return;
    uint8_t status = (uint8_t)((h->flags | FLAG_QUARANTINED) &
                               ~FLAG_ALLOCATED);
    DBG_BROWN("[brown] quarantine off=%zu size=%u\n", off, size);
    write_header(off, size, status);
    write_footer(off, size);
    set_header_extras(off, calculate_data_fingerprint(off, size), 0);
}

static size_t next_block_offset(size_t off, uint32_t size) {
    size_t next = off + size;
    return (next >= g_heap_size) ? g_heap_size : next;
}

static bool block_is_free(const BlockHeader *h) {
    return !(h->flags & FLAG_ALLOCATED) && !(h->flags & FLAG_QUARANTINED);
}

static bool block_is_quarantined(const BlockHeader *h) {
    return (h->flags & FLAG_QUARANTINED) != 0;
}

static void coalesce_with_neighbors(size_t off, BlockHeader *h) {
    uint32_t size = h->size;
    size_t next_off = next_block_offset(off, size);
    if (next_off + HEADER_SIZE <= g_heap_size) {
        BlockHeader *nh = get_block_header(next_off);
        if (nh) {
            block_check_t r = validate_block(next_off, &nh);
            if (r == BLOCK_OK && block_is_free(nh)) {
                size += nh->size;
                build_block(off, size, 0, 0);
                h = get_block_header(off);
                size = h ? h->size : size;
            } else if (r == BLOCK_CORRUPT) {
                quarantine_block(next_off, nh ? nh->size : 0);
            }
        }
    }

    if (off >= FOOTER_SIZE) {
        size_t foff = off - FOOTER_SIZE;
        BlockFooter *pf = (BlockFooter *)(g_heap + foff);
        uint32_t psize = 0;

        if (in_heap(foff, FOOTER_SIZE) &&
            pf->magic == FOOTER_MAGIC && pf->inv_size == ~pf->size)
            psize = pf->size;

        if (psize >= HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD &&
            off >= psize) {
            size_t prev_off = off - psize;
            BlockHeader *ph = get_block_header(prev_off);
            if (ph) {
                if (ph->canary != compute_integrity_key(prev_off, psize)) {
                    DBG_BROWN("[brown] Prev canary mismatch, "
                              "quarantining.\n");
                    quarantine_block(prev_off, psize);
                    return;
                }

                block_check_t r = validate_block(prev_off, &ph);
                if (r == BLOCK_OK && block_is_free(ph)) {
                    size_t new_size = psize + h->size;
                    build_block(prev_off, new_size, 0, 0);
                    off = prev_off;
                    h = get_block_header(off);
                    size = h->size;
                } else if (r == BLOCK_CORRUPT) {
                    quarantine_block(prev_off, ph ? ph->size : 0);
                }
            }
        }
    }
}

static int ensure_ready(void) {
    return g_ready ? 0 : -1;
}

int mm_init(uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
        return -1;

    g_dbg_brown = getenv("MM_BROWNOUT_DEBUG") != NULL;
    if (g_dbg_brown) {
        fprintf(stderr, "[brown] debug enabled\n");
    }

    detect_unused_pattern(heap, heap_size);
    g_pattern_phase = 0;

    g_heap_base = heap;

// Align the working heap start to 40 bytes within the given block
uint8_t *aligned_start = (uint8_t *)align_up((size_t)heap, MM_ALIGNMENT);
size_t skipped = (size_t)(aligned_start - heap);

if (skipped > heap_size) return -1;

size_t usable = heap_size - skipped;
usable = align_down(usable, MM_ALIGNMENT);

if (usable < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
    return -1;

g_heap = aligned_start;
g_heap_size = usable;

    build_block(0, g_heap_size, 0, 0);

    g_ready = true;
    return 0;
}

void *mm_malloc(size_t size) {
    BlockHeader *h = NULL;
    void *ret = NULL;
    LOCK();

    if (ensure_ready() != 0) goto out;
    if (size == 0) size = 1;

    bool did_repair_pass = false;
    size_t payload = 0;
    size_t needed = 0;
    size_t best_off = 0;
    uint32_t best_size = (uint32_t)g_heap_size + 1;

retry:
    payload = align_up(size, MM_ALIGNMENT);
    needed = align_up(payload + HEADER_SIZE + FOOTER_SIZE, MM_ALIGNMENT);
    if (needed > g_heap_size) goto out;

    size_t off = 0;
    while (off + HEADER_SIZE <= g_heap_size) {
        if (off % MM_ALIGNMENT != 0) {
            off = align_up(off, MM_ALIGNMENT);
            continue;
        }

        block_check_t r = validate_block(off, &h);

        if (r == BLOCK_FATAL) {
            DBG_BROWN("[brown] fatal block off=%zu\n", off);
            size_t span = quarantine_span(off, MM_ALIGNMENT);
            off += span ? span : MM_ALIGNMENT;
            continue;
        } else if (r == BLOCK_CORRUPT) {
            uint32_t suspect = h ? h->size : MM_ALIGNMENT;
            if (suspect < MM_ALIGNMENT) suspect = MM_ALIGNMENT;
            DBG_BROWN("[brown] corrupt block off=%zu size=%u\n",
                      off,
                      suspect);
            size_t span = quarantine_span(off, suspect);
            off += span ? span : align_up(suspect, MM_ALIGNMENT);
            continue;
        }

        if (block_is_free(h) && h->size >= needed) {
            if (h->size < best_size) {
                best_size = h->size;
                best_off = off;
            }
        }

        off = next_block_offset(off, h->size);
    }

    if (best_off > 0) {
        off = best_off;
        goto found_block;
    }

    if (!did_repair_pass) {
        did_repair_pass = true;
        size_t roff = 0;
        while (roff + HEADER_SIZE <= g_heap_size) {
            if (roff % MM_ALIGNMENT != 0) {
                roff = align_up(roff, MM_ALIGNMENT);
                continue;
            }
            BlockHeader *rh = NULL;
            block_check_t rr = validate_block(roff, &rh);
            if (rr == BLOCK_FATAL || rr == BLOCK_CORRUPT) {
                uint32_t hint = rh ? rh->size : MM_ALIGNMENT;
                if (hint < MM_ALIGNMENT) hint = MM_ALIGNMENT;
                size_t span = quarantine_span(roff, hint);
                roff += span ? span : MM_ALIGNMENT;
                continue;
            }
            roff = next_block_offset(roff, rh->size);
        }
        goto retry;
    }

found_block:
    h = get_block_header(off);
    if (!h) goto out;

    uint32_t original = h->size;
    uint32_t remain = original - needed;

    if (remain >= HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) {
        build_block(off, needed, FLAG_ALLOCATED, size);
        uint32_t next_block_off = off + needed;
        if (next_block_off % MM_ALIGNMENT != 0) {
            next_block_off = align_up(next_block_off, MM_ALIGNMENT);
            remain = original - (next_block_off - off);
        }
        if (remain >= HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) {
            build_block(next_block_off, remain, 0, 0);
        }
    } else {
        build_block(off, original, FLAG_ALLOCATED, size);
    }

    uint8_t *payload_ptr = g_heap + off + HEADER_SIZE;
    uint64_t payload_offset = (uintptr_t)payload_ptr -
                              (uintptr_t)g_heap_base;
    if (payload_offset % MM_ALIGNMENT != 0) {
        printf("[align-debug] payload misaligned at off=%zu "
               "payload_offset=%" PRIu64 "\n",
               off,
               payload_offset);
        return NULL;
    }
    ret = payload_ptr;

out:
    UNLOCK();
    return ret;
}

static block_check_t validate_payload_ptr(void *ptr,
                                          BlockHeader **out_h,
                                          size_t *out_off) {
    if (ensure_ready() != 0 || !ptr) return BLOCK_FATAL;

    uintptr_t p = (uintptr_t)ptr;
    uintptr_t base = (uintptr_t)g_heap_base;

    if (((p - base) % MM_ALIGNMENT) != 0) {
        printf("[align-debug] payload pointer misaligned: %p\n", ptr);
        return BLOCK_FATAL;
    }

    if (p < base + HEADER_SIZE || p >= base + g_heap_size - FOOTER_SIZE)
        return BLOCK_FATAL;

    size_t off = (p - base) - HEADER_SIZE;
    BlockHeader *h = NULL;
    block_check_t r = validate_block(off, &h);

    if (r != BLOCK_OK) {
        if (recover_header_from_footer(off))
            r = validate_block(off, &h);
        if (r != BLOCK_OK) {
            DBG_BROWN(
                "[brown] payload validate fail off=%zu code=%d\n",
                off,
                (int)r);
            return r;
        }
    }

    if (!h || !(h->flags & FLAG_ALLOCATED) || block_is_quarantined(h))
        return BLOCK_FATAL;

    if (out_h) *out_h = h;
    if (out_off) *out_off = off;
    return BLOCK_OK;
}

int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    int ret = -1;
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    size_t payload = h->size - HEADER_SIZE - FOOTER_SIZE;
    if (offset + len > payload) goto out;

    if (calculate_data_fingerprint(off, h->size) !=
        h->integrity_check_value) {
        DBG_BROWN("[brown] read hash mismatch off=%zu size=%u\n",
                  off,
                  h->size);
        quarantine_block(off, h->size);
        goto out;
    }

    memcpy(buf, (uint8_t *)ptr + offset, len);
    ret = (int)len;

out:
    UNLOCK();
    return ret;
}

int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    int ret = -1;
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    size_t requested_size = h->client_size_request;
    if (offset + len != requested_size) goto out;

    if (calculate_data_fingerprint(off, h->size) !=
        h->integrity_check_value) {
        DBG_BROWN(
            "[brown] write hash mismatch off=%zu size=%u\n",
            off, h->size);
        quarantine_block(off, h->size);
        goto out;
    }

    memcpy((uint8_t *)ptr + offset, src, len);

    set_header_extras(off, calculate_data_fingerprint(off, h->size),
                      h->client_size_request);
    ret = (int)len;

out:
    UNLOCK();
    return ret;
}

void mm_free(void *ptr) {
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    if (!h || !h->flags || block_is_quarantined(h)) goto out;

    build_block(off, h->size, 0, 0);
    h = get_block_header(off);
    if (h) coalesce_with_neighbors(off, h);

out:
    UNLOCK();
}

void *mm_realloc(void *ptr, size_t new_size) {
    if (!ptr) return mm_malloc(new_size);
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    BlockHeader *h = NULL;
    size_t off = 0;
    size_t old_payload = 0;

    LOCK();
    if (validate_payload_ptr(ptr, &h, &off) != BLOCK_OK) {
        UNLOCK();
        return NULL;
    }
    old_payload = h->size - HEADER_SIZE - FOOTER_SIZE;
    if (new_size <= old_payload) {
        UNLOCK();
        return ptr;
    }
    UNLOCK();

    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    size_t to_copy = old_payload < new_size ? old_payload : new_size;
    memcpy(new_ptr, ptr, to_copy);

    size_t new_off = ((uint8_t *)new_ptr - g_heap) - HEADER_SIZE;
    LOCK();
    BlockHeader *nh = get_block_header(new_off);
    if (nh) {
        set_header_extras(new_off,
                          calculate_data_fingerprint(new_off, nh->size),
                          nh->client_size_request);
    }
    UNLOCK();

    mm_free(ptr);
    return new_ptr;
}

void mm_heap_stats(void) {
    LOCK();

    if (!g_ready) {
        printf("Heap not initialized\n");
        goto out;
    }

    size_t off = 0;
    size_t free_bytes = 0, alloc_bytes = 0, quarant_bytes = 0;
    size_t blocks = 0, corrupt = 0;
    size_t misalign_headers = 0, misalign_payloads = 0;

    while (off + HEADER_SIZE <= g_heap_size) {
        BlockHeader *h = NULL;
        block_check_t r = validate_block(off, &h);

        if (r == BLOCK_FATAL) {
            corrupt++;
            off += MM_ALIGNMENT;
            continue;
        }
        if (r == BLOCK_CORRUPT) {
            corrupt++;
            size_t step = h && h->size >= HEADER_SIZE ? h->size :
                          MM_ALIGNMENT;
            off += align_up(step, MM_ALIGNMENT);
            continue;
        }

        if (off % MM_ALIGNMENT != 0) misalign_headers++;
        uint8_t *payload = g_heap + off + HEADER_SIZE;
        if (((uintptr_t)payload - (uintptr_t)g_heap_base) %
            MM_ALIGNMENT != 0)
            misalign_payloads++;

        blocks++;
        if (block_is_quarantined(h))      quarant_bytes += h->size;
        else if (block_is_free(h))        free_bytes += h->size;
        else                               alloc_bytes += h->size;

        off = next_block_offset(off, h->size);
    }

    printf("Heap size: %zu bytes\n", g_heap_size);
    printf("Blocks: %zu (alloc=%zu, free=%zu, quarantined=%zu, "
           "corrupt=%zu)\n",
           blocks, alloc_bytes, free_bytes, quarant_bytes, corrupt);

    if (misalign_headers || misalign_payloads) {
        printf("[align-debug] misaligned headers=%zu payloads=%zu\n",
               misalign_headers, misalign_payloads);
    }

out:
    UNLOCK();
}

void mm_heap_dump(int verbose) {
    (void)verbose;
    LOCK();

    if (!g_ready) {
        printf("Heap not initialized\n");
        goto out;
    }

    size_t off = 0;
    int idx = 0;

    printf("Heap dump (size=%zu):\n", g_heap_size);

    while (off + HEADER_SIZE <= g_heap_size) {
        if (off % MM_ALIGNMENT != 0) {
            off = align_up(off, MM_ALIGNMENT);
            continue;
        }

        BlockHeader *h = NULL;
        block_check_t r = validate_block(off, &h);

        if (r == BLOCK_FATAL) {
            printf("[%02d] off=%zu FATAL\n", idx++, off);
            off += MM_ALIGNMENT;
            continue;
        }
        if (r == BLOCK_CORRUPT) {
            printf("[%02d] off=%zu CORRUPT size=%u\n", idx++, off,
                   h ? h->size : 0);
            size_t step = (h && h->size >= HEADER_SIZE) ? h->size :
                          MM_ALIGNMENT;
            off += align_up(step, MM_ALIGNMENT);
            continue;
        }

        uint32_t sz = h->size;
        const char *state = block_is_quarantined(h) ? "QUAR" :
                             block_is_free(h)        ? "FREE" : "ALLOC";

        uint8_t *payload = g_heap + off + HEADER_SIZE;
        size_t payload_mod = ((uintptr_t)payload - (uintptr_t)g_heap_base) %
                             MM_ALIGNMENT;
        printf("[%02d] off=%-8zu size=%-8u state=%5s header_mod=%2zu "
               "payload_mod=%2zu\n",
               idx++,
               off,
               sz,
               state,
               off % MM_ALIGNMENT,
               payload_mod);

        off = next_block_offset(off, sz);
    }

out:
    UNLOCK();
}
