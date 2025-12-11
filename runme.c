#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "allocator.h"

int main(int argc, char **argv) {
    size_t heap_size = 32768;
    int storm_count = 0;
    unsigned int seed = (unsigned int)time(NULL);

    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--size") == 0) {
            heap_size = (size_t)strtoull(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--storm") == 0) {
            storm_count = (int)strtol(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--seed") == 0) {
            seed = (unsigned int)strtoul(argv[i + 1], NULL, 10);
        }
    }

    srand(seed);
    printf("[INFO] Heap size: %zu bytes\n", heap_size);
    printf("[INFO] Storm iterations: %d\n", storm_count);
    printf("[INFO] Random seed: %u\n", seed);

    // Allocate contiguous heap block using host OS malloc
    uint8_t *heap = (uint8_t *)malloc(heap_size);
    if (!heap) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    // Initialize heap with unused pattern before calling mm_init
    static const uint8_t pattern[5] = {0xA5, 0x5A, 0x3C, 0xC3, 0x7E};
    for (size_t i = 0; i < heap_size; ++i) heap[i] = pattern[i % 5];

    // Initialize the allocator with the heap block
    if (mm_init(heap, heap_size) != 0) {
        fprintf(stderr, "mm_init failed\n");
        free(heap);
        return 1;
    }

    printf("\n[TEST] Single block: requested 64 bytes\n");
    void *p = mm_malloc(64);
    if (p) {
        const char msg[] = "test";
        int r1 = mm_write(p, 0, msg, sizeof(msg));
        int r2 = mm_write(p, 10, msg, 4);
        int r3 = mm_write(p, 60, msg, 4);
        int r4 = mm_write(p, 63, msg, 1);
        int r5 = mm_write(p, 64, msg, 1);
        printf("[TEST] Write results: %d %d %d %d\n", r1, r2, r3, r4);
        printf("[TEST] Out of bounds write return value: %d\n", r5);
        mm_free(p);
    }

    void *p1 = mm_malloc(32);
    void *p2 = mm_malloc(128);
    void *p3 = mm_malloc(256);
    if (p1) {
        printf("\n[TEST] Heap 1: requested 32 bytes\n");
        int r1 = mm_write(p1, 0, "A", 1);
        int r2 = mm_write(p1, 31, "B", 1);
        int r3 = mm_write(p1, 32, "C", 1);
        printf("[TEST] Heap 1 write results: %d %d\n", r1, r2);
        printf("[TEST] Heap 1 out of bounds: %d\n", r3);
        mm_free(p1);
    }
    if (p2) {
        printf("\n[TEST] Heap 2: requested 128 bytes\n");
        int r1 = mm_write(p2, 0, "X", 1);
        int r2 = mm_write(p2, 127, "Y", 1);
        int r3 = mm_write(p2, 128, "Z", 1);
        printf("[TEST] Heap 2 write results: %d %d\n", r1, r2);
        printf("[TEST] Heap 2 out of bounds: %d\n", r3);
        mm_free(p2);
    }
    if (p3) {
        printf("\n[TEST] Heap 3: requested 256 bytes\n");
        int r1 = mm_write(p3, 0, "M", 1);
        int r2 = mm_write(p3, 255, "N", 1);
        int r3 = mm_write(p3, 256, "O", 1);
        printf("[TEST] Heap 3 write results: %d %d\n", r1, r2);
        printf("[TEST] Heap 3 out of bounds: %d\n", r3);
        mm_free(p3);
    }

    if (storm_count > 0) {
        printf("\n[STORM] Running %d iterations of stress test\n", storm_count);
        void *ptrs[100];
        int ptr_count = 0;

        for (int iter = 0; iter < storm_count; ++iter) {
            int action = rand() % 3;

            if (action == 0 && ptr_count < 100) {
                size_t req_size = (rand() % 256) + 16;
                void *ptr = mm_malloc(req_size);
                if (ptr) {
                    ptrs[ptr_count++] = ptr;
                    printf("[STORM] Iteration %d: malloc(%zu) -> %p\n",
                           iter, req_size, ptr);
                }
            } else if (action == 1 && ptr_count > 0) {
                int idx = rand() % ptr_count;
                void *ptr = ptrs[idx];
                ptrs[idx] = ptrs[--ptr_count];
                mm_free(ptr);
                printf("[STORM] Iteration %d: free(%p)\n", iter, ptr);
            } else if (action == 2 && ptr_count > 0) {
                int idx = rand() % ptr_count;
                void *ptr = ptrs[idx];
                size_t offset = rand() % 64;
                uint8_t data = (uint8_t)rand();
                int r = mm_write(ptr, offset, &data, 1);
                printf("[STORM] Iteration %d: write(%p, %zu) -> %d\n",
                       iter, ptr, offset, r);
            }
        }

        for (int i = 0; i < ptr_count; ++i) {
            mm_free(ptrs[i]);
        }
        printf("[STORM] Stress test complete\n");
    }

    free(heap);  // Release allocated host heap
    return 0;
}
