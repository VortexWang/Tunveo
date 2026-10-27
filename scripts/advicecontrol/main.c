#define _GNU_SOURCE
#include <sys/mman.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#define M (1024UL*1024)
__attribute__((noinline)) void *control_mmap(void *a,size_t n,int p,int f,int d,long o){
 void *r=mmap(a,n,p,f,d,o);__asm__ volatile("" : "+r"(r));return r;
}
__attribute__((noinline)) void *control_trace(void *a,size_t n){
 void *r=control_mmap(a,n,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,-1,0);__asm__ volatile("" : "+r"(r));return r;
}
__attribute__((noinline)) void *control_other(void *a,size_t n){
 void *r=control_mmap(a,n,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,-1,0);__asm__ volatile("" : "+r"(r));return r;
}
static void touch(void *p){if(p==MAP_FAILED)exit(2);for(size_t i=0;i<4*M;i+=4096)((volatile char*)p)[i]=7;}
static void mark(const char *dir,const char *phase,uintptr_t base){
 char tmp[4096],out[4096];snprintf(tmp,sizeof(tmp),"%s/marker.tmp",dir);snprintf(out,sizeof(out),"%s/marker.json",dir);
 struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);FILE *f=fopen(tmp,"w");if(!f)exit(3);
 fprintf(f,"{\"phase\":\"%s\",\"base\":%lu,\"current\":%lu,\"monotonic_ns\":%lu}\n",phase,(unsigned long)base,(unsigned long)base,(unsigned long)t.tv_sec*1000000000UL+t.tv_nsec);
 if(fclose(f)||rename(tmp,out))exit(4);usleep(400000);
}
int main(int argc,char **argv){
 if(argc!=2)return 1;
 void *reserve=mmap(NULL,6*M,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(reserve==MAP_FAILED)return 2;
 char *base=(char*)reserve+M;touch(control_trace(base,4*M));mark(argv[1],"held",(uintptr_t)base);
 if(madvise(base,4*M,MADV_DONTNEED))return 5;mark(argv[1],"discarded",(uintptr_t)base);
 errno=0;if(madvise(base+1,4096,MADV_DONTNEED)!=-1||errno!=EINVAL)return 6;mark(argv[1],"failed",(uintptr_t)base);
 touch(base);mark(argv[1],"retouched",(uintptr_t)base);
 if(munmap(base,4*M))return 7;touch(control_other(base,4*M));mark(argv[1],"reused",(uintptr_t)base);
 if(madvise(base,4*M,MADV_DONTNEED))return 8;mark(argv[1],"reused_discarded",(uintptr_t)base);
 if(munmap(base,4*M))return 9;mark(argv[1],"released",(uintptr_t)base);
 if(munmap(reserve,6*M))return 10;return 0;
}
