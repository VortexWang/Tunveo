#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((noinline)) void *control_map(size_t n,const char *tag,int unused) {
    (void)tag;(void)unused;
    void *p=mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) abort();
    return p;
}
__attribute__((noinline)) void *control_site(size_t n) {
    void *p=control_map(n,"TracePart-control",0);
    __asm__ volatile("" : "+r"(p) : : "memory");
    return p;
}
__attribute__((noinline)) void *control_aligned(size_t size,size_t alignment,const char *tag) {
    (void)tag;size_t total=size+alignment;
    void *raw=mmap(NULL,total,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(raw==MAP_FAILED)abort();
    uintptr_t base=(uintptr_t)raw,ptr=(base+alignment-1)&~(alignment-1);
    if(ptr>base && munmap((void*)base,ptr-base))abort();
    if(ptr+size<base+total && munmap((void*)(ptr+size),base+total-ptr-size))abort();
    __asm__ volatile("" : "+r"(ptr) : : "memory");
    return (void*)ptr;
}
__attribute__((noinline)) void *control_batch(void *allocator,void *stats,void *cache,size_t cl) {
    (void)allocator;(void)stats;(void)cache;
    void *p=control_aligned((size_t)4096<<cl,(size_t)4096<<cl,"Aligned-control");
    __asm__ volatile("" : "+r"(p) : : "memory");
    return p;
}
static pthread_barrier_t barrier;
/* Keep all four TIDs but avoid cross-thread reuse during syscall exit probes.
 * The production auditor still rejects ambiguous overlapping memory operations. */
static pthread_mutex_t mapping_lock=PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *unused) {
    (void)unused;
    int b=pthread_barrier_wait(&barrier);if(b!=0 && b!=PTHREAD_BARRIER_SERIAL_THREAD)abort();
    for(size_t i=0;i<8;i++) {
        if(pthread_mutex_lock(&mapping_lock))abort();
        size_t n=(size_t)4096<<i;void *p=control_batch(NULL,NULL,NULL,i);
        ((volatile char*)p)[0]=1;
        printf("{\"tid\":%ld,\"size\":%zu,\"alignment\":%zu,\"pointer\":%llu}\n",syscall(SYS_gettid),n,n,(unsigned long long)(uintptr_t)p);
        if(munmap(p,n))abort();
        if(pthread_mutex_unlock(&mapping_lock))abort();
    }
    return NULL;
}
int main(void) {
    void *p=control_site(131072);if(munmap(p,131072))abort();
    pthread_t t[4];if(pthread_barrier_init(&barrier,NULL,4))abort();
    for(int i=0;i<4;i++)if(pthread_create(&t[i],NULL,worker,NULL))abort();
    for(int i=0;i<4;i++)if(pthread_join(t[i],NULL))abort();
    if(pthread_barrier_destroy(&barrier))abort();
    return 0;
}
