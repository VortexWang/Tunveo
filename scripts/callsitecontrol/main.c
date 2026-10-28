#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* The compiler must preserve this direct call and its following instruction. */
__attribute__((noinline)) void *control_map(size_t size, const char *tag, int unused) {
    (void)tag; (void)unused;
    void *p=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    __asm__ volatile("" : "+r"(p));
    return p;
}
__attribute__((noinline)) void *control_site(size_t size) {
    void *p=control_map(size,"KnownControl",0);
    __asm__ volatile("" : "+r"(p));
    return p;
}
static void *worker(void *arg) {
    size_t base=(size_t)(uintptr_t)arg;
    for(size_t i=1;i<=8;i++) {
        size_t size=(base*8+i)*4096;
        unsigned char *p=control_site(size);
        if(p==MAP_FAILED) exit(2);
        for(size_t j=0;j<size;j+=4096) p[j]=7;
        printf("{\"tid\":%ld,\"size\":%zu,\"pointer\":%lu}\n",syscall(SYS_gettid),size,(unsigned long)(uintptr_t)p);
        if(munmap(p,size)) exit(3);
    }
    return NULL;
}
int main(void) {
    pthread_t threads[4];
    for(uintptr_t i=0;i<4;i++) if(pthread_create(&threads[i],NULL,worker,(void*)i)) return 4;
    for(size_t i=0;i<4;i++) if(pthread_join(threads[i],NULL)) return 5;
    return 0;
}
