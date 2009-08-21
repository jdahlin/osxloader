#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "macho.h"

static void
map_segment_command(FILE *fp, const struct segment_command *command)
{
    int mmap_prot = 0;

    fprintf(stderr, "name: %-16s prot: 0x%02x, size: 0x%04x, off: 0x%04x\n",
            command->segname, command->initprot, command->cmdsize,
            command->fileoff);

    if (command->initprot & VM_PROT_READ)
        mmap_prot |= PROT_READ;
    if (command->initprot & VM_PROT_WRITE)
        mmap_prot |= PROT_WRITE;
    if (command->initprot & VM_PROT_EXECUTE)
        mmap_prot |= PROT_EXEC;

    if (!strcmp(command->segname, "__PAGEZERO")) {
        int fd = open("/dev/zero", O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "failed to open /dev/zero for reading: %s\n",
                    strerror(errno));
            return;
        }
        errno = 0;
        if (mmap(NULL, command->vmsize, mmap_prot,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANON, fd, 0) == (void*)-1) {
            fprintf(stderr, "failed to map page zero segment: %s\n",
                    strerror(errno));
        }
        close(fd);
        return;
    }

    if (mmap((void*)command->vmaddr, command->filesize, mmap_prot,
             MAP_FIXED | MAP_PRIVATE, fileno(fp),
             /* fixme: fat offset*/ 0 + command->fileoff) == (void*)-1) {
            fprintf(stderr, "failed to map %s segment: %s\n",
                    command->segname, strerror(errno));
    }
}

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
        case LC_SEGMENT: {
            struct segment_command *segcmd = (struct segment_command*)loadcmd;
            map_segment_command(fp, segcmd);
            break;
        }
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
