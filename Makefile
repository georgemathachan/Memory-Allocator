CC = gcc
# Put -pthread in CFLAGS so pthread symbols are available at
# compile time as well as link.
CFLAGS = -std=c11 -Wall -Wextra -pedantic -fPIC -O2 -pthread

# Shared linker flags
LDFLAGS_SHARED = -shared
# Other linker flags (for executables)
LDFLAGS = -pthread

all: liballocator.so runme

allocator.o: allocator.c allocator.h
	$(CC) $(CFLAGS) -c allocator.c -o allocator.o

# Build shared library from the PIC object and
# explicitly pass -shared and -pthread
liballocator.so: allocator.o
	$(CC) $(CFLAGS) $(LDFLAGS_SHARED) -o liballocator.so allocator.o $(LDFLAGS)

runme.o: runme.c allocator.h
	$(CC) $(CFLAGS) -c runme.c -o runme.o

# Link runme; include allocator.o
# (or change to link against liballocator.so if desired)
runme: runme.o allocator.o
	$(CC) $(CFLAGS) -o runme runme.o allocator.o $(LDFLAGS)

.PHONY: all test clean

test: runme
	./runme --size 32768 --storm 10 --seed 1

clean:
	rm -f *.o liballocator.so runme
