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

    header = (struct mach_header*)malloc(sizeof(header));
    if (fread(header, 1, sizeof(header), fp) != sizeof(header)) {
        fprintf(stderr, "error reading file: %s\n", strerror(errno));
    }

    if (header->magic != MACHO_MAGIC) {
        fprintf(stderr, "error: %s is not a Mach-O binary.\n", filename);
        free(header);
        return 1;
    }

    free(header);
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
