#define _GNU_SOURCE
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 4 || (strcmp(argv[1], "keep") && strcmp(argv[1], "disable"))) return 2;
    int before = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if (before != 0) { fprintf(stderr, "THP control requires inherited PR_GET_THP_DISABLE=0, got %d\n", before); return 2; }
    int wanted = !strcmp(argv[1], "disable");
    if (wanted && prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) { perror("PR_SET_THP_DISABLE"); return 2; }
    int after = prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if (after != wanted) { fprintf(stderr, "THP control readback mismatch\n"); return 2; }
    FILE *f = fopen(argv[2], "wx");
    if (!f) { perror("control evidence"); return 2; }
    if (fprintf(f, "{\"pid\":%ld,\"before\":%d,\"after\":%d}\n", (long)getpid(), before, after) < 0 || fclose(f)) return 2;
    execv(argv[3], &argv[3]);
    perror("execv"); return 2;
}
