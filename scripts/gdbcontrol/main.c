/* Diagnostic fixture only, never linked into the engine. */
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) void *control_mmap(void *addr, size_t size, int prot,
                                          int flags, int fd, long offset) {
    void *result = mmap(addr, size, prot, flags, fd, offset);
    __asm__ volatile("" : "+r"(result));
    return result;
}
__attribute__((noinline)) uintptr_t control_parent(size_t size) {
    volatile unsigned char *p = control_mmap(NULL, size, PROT_READ|PROT_WRITE,
                                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) exit(2);
    unsigned long sum = 0;
    for (size_t i=0; i<size; i+=4096) { p[i]=7; sum+=p[i]; }
    uintptr_t address=(uintptr_t)p;
    printf("{\"address\":%lu,\"size\":%lu,\"touched_pages\":%lu,\"checksum\":%lu}\n",
           (unsigned long)address,(unsigned long)size,(unsigned long)(size/4096),sum);
    if (munmap((void*)p,size)) exit(3);
    return address;
}
int main(void) { return control_parent(1048576) == 0; }
