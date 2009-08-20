#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "macho.h"

static int
open_executable(const char * filename)
{
    FILE *fp;
    struct mach_header *header = NULL;
    struct load_command *loadcmds = NULL, *loadcmd;
    int i;

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
        goto error;
    }

    if (header->magic != MH_MAGIC) {
        fprintf(stderr, "error: %s is not a Mach-O binary (magic was %x).\n",
                filename, header->magic);
        goto error;
    }

#ifdef __i386__
    if (header->cputype != CPU_TYPE_X86) {
        fprintf(stderr, "error: %s is not a x86 binary (cputype: %d).\n",
                filename, header->cputype);
        goto error;
    }
#else
#  error "unsupported architecture"
#endif

    switch (header->filetype) {
      case MH_EXECUTE:
        break;
      default:
        fprintf(stderr, "ERROR: Unsupported Mach-O file types: %d\n", header->filetype);
        goto error;
    }

    loadcmds = malloc(header->sizeofcmds);
    if (fread(loadcmds, header->sizeofcmds, 1, fp) < 0) {
        fprintf(stderr, "error reading file: %s\n", strerror(errno));
        goto error;
    }

    for (i = 0, loadcmd = loadcmds; i < header->ncmds; ++i,
         loadcmd = (struct load_command*)((int)(loadcmd)+(loadcmd->cmdsize))) {
        switch(loadcmd->cmd) {
        case LC_SEGMENT:
            break;
        case LC_SYMTAB:
            break;
        case LC_UNIXTHREAD: {
            struct thread_command *threadcmd = (struct thread_command*)loadcmd;
            fprintf(stderr, "eip: 0x%x\n", threadcmd->state.eip);
            break;
        }
        case LC_DYSYMTAB:
            break;
        case LC_LOAD_DYLINKER:
            break;
        case LC_LOAD_DYLIB:
            break;
        case LC_UUID:
            break;
        default:
            fprintf(stderr, "load command 0x%02x not supported\n", loadcmd->cmd);
            break;
        }
    }

error:
    if (loadcmds)
        free(loadcmds);
    if (header)
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
