#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "macho.h"

#define STACK_SIZE (8192 * 1024)

typedef struct {
    struct load_command *loadcmds;
    const struct thread_command* threadcmd;
    const struct dysymtab_command* dysymtabcmd;
    const struct segment_command *linkeditcmd;
    const char *filename;
    struct mach_header *header;
    const char *symbol_strings;
    struct nlist* symbols;
    int n_symbols;
    FILE *fp;
    int stack_base;
} Loader;

static Loader *
loader_new()
{
    Loader *loader = (Loader *)malloc(sizeof(Loader));
    bzero(loader, sizeof(Loader));
    return loader;
}

static void
loader_free(Loader *loader)
{
    if (loader->loadcmds)
        free(loader->loadcmds);
    if (loader->header)
        free(loader->header);
    fclose(loader->fp);
}

static void
loader_map_segment_command(Loader *loader,
                           const struct segment_command *command)
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
             MAP_FIXED | MAP_PRIVATE, fileno(loader->fp),
             /* fixme: fat offset*/ 0 + command->fileoff) == (void*)-1) {
            fprintf(stderr, "failed to map %s segment: %s\n",
                    command->segname, strerror(errno));
    }
}

static int
loader_parse_header(Loader *loader, const char *filename)
{
    loader->filename = filename;

    loader->fp = fopen(filename, "r");
    if (!loader->fp) {
        fprintf(stderr, "error opening file: %s\n", strerror(errno));
        return 1;
    }

    loader->header = (struct mach_header*)malloc(sizeof(struct mach_header));
    errno = 0;
    fread(loader->header, sizeof(struct mach_header), 1, loader->fp);
    if (errno) {
        fprintf(stderr, "error reading file: %s\n", strerror(errno));
        return 1;
    }

    if (loader->header->magic != MH_MAGIC) {
        fprintf(stderr, "error: %s is not a Mach-O binary (magic was %x).\n",
                filename, loader->header->magic);
        return 1;
    }

#ifdef __i386__
    if (loader->header->cputype != CPU_TYPE_X86) {
        fprintf(stderr, "error: %s is not a x86 binary (cputype: %d).\n",
                loader->filename, loader->header->cputype);
        return 1;
    }
#else
#  error "unsupported architecture"
#endif

    switch (loader->header->filetype) {
      case MH_EXECUTE:
        break;
      default:
        fprintf(stderr, "ERROR: Unsupported Mach-O file types: %d\n",
                loader->header->filetype);
        return 1;
    }

    return 0;
}

static int
loader_parse_commands(Loader *loader)
{
    struct load_command *loadcmd;
    int i;

    loader->loadcmds = malloc(loader->header->sizeofcmds);

    if (fread(loader->loadcmds,
              loader->header->sizeofcmds, 1, loader->fp) < 0) {
        fprintf(stderr, "error reading file: %s\n", strerror(errno));
        return 1;
    }

    for (i = 0, loadcmd = loader->loadcmds; i < loader->header->ncmds; ++i,
        loadcmd = (struct load_command*)((int)(loadcmd)+(loadcmd->cmdsize))) {
        switch(loadcmd->cmd) {
        case LC_SEGMENT: {
            struct segment_command *segcmd = (struct segment_command*)loadcmd;
            loader_map_segment_command(loader, segcmd);
            if (!strcmp(segcmd->segname, "__LINKEDIT"))
                loader->linkeditcmd = segcmd;
	        struct section *section, *last, *sections = (struct section*)
	            ((char*)segcmd + sizeof(struct segment_command));
	        last = &sections[segcmd->nsects];
	        for (section = sections; section < last; ++section) {
		        printf(" - section: %s\n", section->sectname);
	        }
            break;
        }
        case LC_SYMTAB: {
            struct symtab_command* symtab = (struct symtab_command*)loadcmd;
            const uint8_t* linkedit = (uint8_t*)(loader->linkeditcmd->vmaddr -
                                           loader->linkeditcmd->fileoff);
            loader->symbol_strings = (const char*)&linkedit[symtab->stroff];
            loader->symbols = (struct nlist*)(&linkedit[symtab->symoff]);
            loader->n_symbols = symtab->nsyms;
            break;
        }
        case LC_UNIXTHREAD: {
            loader->threadcmd = (struct thread_command*)loadcmd;
            break;
        }
        case LC_DYSYMTAB:
            loader->dysymtabcmd = (struct dysymtab_command*)loadcmd;
            break;
        case LC_LOAD_DYLINKER:
            break;
        case LC_LOAD_DYLIB:
            break;
        case LC_UUID:
            break;
        default:
            fprintf(stderr, "load command 0x%02x not supported\n", loadcmd->cmd);
            return 1;
        }
    }
    return 0;
}

static int
loader_create_stack(Loader *loader)
{
    int * stack;

    stack = mmap(0, STACK_SIZE,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
    if (stack == (void*)-1) {
        fprintf(stderr, "failed to map page zero segment: %s\n",
                strerror(errno));
	    return 1;
    }

    bzero(stack, STACK_SIZE);
    loader->stack_base = (int)stack + STACK_SIZE;

    return 0;
}

static int
loader_bind_indirect_symbols(Loader *loader)
{
    struct load_command *loadcmd;
    int i, j;
    struct segment_command *segcmd;
    struct section *section, *last, *sections;
    uint8_t* linkedit = (uint8_t*)(loader->linkeditcmd->vmaddr -
                                   loader->linkeditcmd->fileoff);
    uint8_t* entry;
    uint32_t* indirect_table = (uint32_t*)&linkedit[loader->dysymtabcmd->indirectsymoff];

    static void *handle = NULL;

    for (i = 0, loadcmd = loader->loadcmds; i < loader->header->ncmds; ++i,
        loadcmd = (struct load_command*)((int)(loadcmd)+(loadcmd->cmdsize))) {
        if (loadcmd->cmd != LC_SEGMENT)
            continue;
        segcmd = (struct segment_command*)loadcmd;
        sections = (struct section*)((char*)segcmd + sizeof(struct segment_command));
        last = &sections[segcmd->nsects];
        for (section = sections; section < last; ++section) {
            uint8_t* start = (uint8_t*)(section->addr);
            uint8_t* end = start + section->size;
            uint32_t indirect_offset = section->reserved1;
            uint8_t type = section->flags & SECTION_TYPE;
            if ((type != S_SYMBOL_STUBS) ||
                !(section->flags & S_ATTR_SELF_MODIFYING_CODE) ||
                (section->reserved2 != 5)) {
                continue;
            }

            for (j = 0, entry = start; entry < end; entry += 5, ++j) {
                uint32_t symbol;
                const char* symbol_name;
                uint32_t symbol_address;
                uintptr_t func;

                symbol = indirect_table[indirect_offset + j];
                if (symbol >= loader->n_symbols)
                    break;
                symbol_name = &loader->symbol_strings[loader->symbols[symbol].n_strx];
                if (!handle)
                    handle = dlopen(NULL, 0);
                func = dlsym(handle, symbol_name + 1);
                if (!func) {
                    fprintf(stderr, "undefined symbol: %s\n", symbol_name);
                    return 1;
                }
                uint32_t rel32 = func - (((uint32_t)entry)+5);

                entry[0] = 0xE9; // JMP rel32
                entry[1] = rel32 & 0xFF;
                entry[2] = (rel32 >> 8) & 0xFF;
                entry[3] = (rel32 >> 16) & 0xFF;
                entry[4] = (rel32 >> 24) & 0xFF;
            }
        }
    }
    return 0;
}

static inline void
loader_execute(Loader *loader)
{
    char **env, **argv;
    int argc;

    env = malloc(sizeof(char*));
    env[0] = NULL;

    argc = 1;
    argv = malloc(sizeof(char*));
    argv[0] = strdup(loader->filename);

    __asm__("push %0" : : "g" (argc));
    __asm__("push %0" : : "g" (argv[0]));
    __asm__("push %0" : : "g" (0));
    __asm__("push %0" : : "g" (env[0]));
    __asm__("push %0" : : "g" (0));
    __asm__("push %0" : : "g" (argv[0]));
    __asm__("push %0" : : "g" (0));

#if 0
    __asm__("int $03");
#endif
    /* jump to the executable entry point, start: */
    __asm__("jmp *%0" : : "g" (loader->threadcmd->state.eip));

    free(argv[0]);
    free(env);
    free(argv);
}

int main(int argc, char **argv)
{
    Loader *loader;

    if (argc < 2) {
        fprintf(stderr, "usage: %s binary [args]\n", argv[0]);
        return 1;
    }

    loader = loader_new();
    if (loader_parse_header(loader, argv[1])) {
	    loader_free(loader);
	    return 1;
    }

    if (loader_parse_commands(loader)) {
	    loader_free(loader);
	    return 1;
    }

    if (loader_create_stack(loader)) {
	    loader_free(loader);
	    return 1;
    }

    if (loader_bind_indirect_symbols(loader)) {
	    loader_free(loader);
	    return 1;
    }

    loader_execute(loader);

    loader_free(loader);

    return 0;
}
