#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "macho.h"

static int
open_executable(const char * filename)
{
    FILE *fp;
    struct mach_header *header;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "error opening file: %s\n", strerror(errno));
        return 1;
    }

    header = (struct mach_header*)malloc(sizeof(struct mach_header));
    errno = 0;
    fread(header, sizeof(struct mach_header), 1, fp);
    if (errno) {
        fprintf(stderr, "error reading file: %s\n", strerror(errno));
        free(header);
        fclose(fp);
        return 1;
    }

    if (header->magic != MH_MAGIC) {
        fprintf(stderr, "error: %s is not a Mach-O binary.\n", filename);
        free(header);
        fclose(fp);
        return 1;
    }

    fprintf(stderr, "CPU type: %d %d\n", header->cputype, header->cpusubtype);

    free(header);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s binary [args]\n", argv[0]);
        return 1;
    }

    return open_executable(argv[1]);
}
