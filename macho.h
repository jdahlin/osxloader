#include <stdint.h>

#define MACHO_MAGIC 0xfeedface

struct mach_header
   {
   uint32_t magic;
   int cputype;
   int cpusubtype;
   uint32_t filetype;
   uint32_t ncmds;
   uint32_t sizeofcmds;
   uint32_t flags;
};

