#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#define M (1024UL*1024)
static void *desired;
__attribute__((noinline)) void *control_map(size_t size,const char *tag,int unused) {
    (void)tag;(void)unused;
    void *p=mmap(desired,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    __asm__ volatile("" : "+r"(p));return p;
}
__attribute__((noinline)) void *control_site(size_t size) {
    void *p=control_map(size,"LifecycleControl",0);
    __asm__ volatile("" : "+r"(p));return p;
}
static void touch(void *p,size_t n) {for(size_t i=0;i<n;i+=4096)((volatile unsigned char*)p)[i]=7;}
static void marker(const char *folder,const char *phase,void *base,void *current) {
    char tmp[4096],out[4096];struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts))exit(11);
    if(snprintf(tmp,sizeof(tmp),"%s/marker.tmp",folder)>=(int)sizeof(tmp)||snprintf(out,sizeof(out),"%s/marker.json",folder)>=(int)sizeof(out))exit(12);
    FILE *f=fopen(tmp,"w");if(!f)exit(13);
    fprintf(f,"{\"phase\":\"%s\",\"base\":%lu,\"current\":%lu,\"monotonic_ns\":%llu}\n",phase,(unsigned long)(uintptr_t)base,(unsigned long)(uintptr_t)current,(unsigned long long)ts.tv_sec*1000000000ULL+ts.tv_nsec);
    if(fclose(f)||rename(tmp,out))exit(14);
    usleep(400000);
}
int main(int argc,char **argv) {
    if(argc!=2)return 1;
    void *reservation=mmap(NULL,6*M,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(reservation==MAP_FAILED)return 2;
    desired=(char*)reservation+M;void *base=control_site(4*M);
    if(base!=desired)return 3;
    touch(base,4*M);marker(argv[1],"held",base,base);
    if(madvise(base,4*M,MADV_DONTNEED))return 4;
    marker(argv[1],"discarded",base,base);
    errno=0;if(madvise((char*)base+1,4096,MADV_DONTNEED)!=-1||errno!=EINVAL)return 5;
    marker(argv[1],"failed_advice",base,base);
    touch(base,4*M);marker(argv[1],"retouched",base,base);
    if(munmap((char*)base+M,2*M))return 6;
    marker(argv[1],"hole",base,base);
    void *reuse=mmap((char*)base+M,2*M,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if(reuse!=(char*)base+M)return 7;
    touch(reuse,2*M);marker(argv[1],"reused",base,reuse);
    void *target=mmap(NULL,6*M,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(target==MAP_FAILED)return 8;
    void *moved=mremap(reuse,2*M,4*M,MREMAP_MAYMOVE|MREMAP_FIXED,(char*)target+M);
    if(moved!=(char*)target+M)return 9;
    touch(moved,4*M);marker(argv[1],"moved",base,moved);
    if(munmap(moved,4*M))return 10;
    marker(argv[1],"released",base,moved);
    if(munmap(reservation,6*M)||munmap(target,6*M))return 15;
    printf("{\"status\":\"passed\",\"base\":%lu,\"moved\":%lu}\n",(unsigned long)(uintptr_t)base,(unsigned long)(uintptr_t)moved);return 0;
}
