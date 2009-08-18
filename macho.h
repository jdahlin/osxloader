#include <stdint.h>

#define MH_MAGIC 0xfeedface

struct mach_header
   {
   uint32_t magic;
   uint32_t cputype;
   uint32_t cpusubtype;
   uint32_t filetype;
   uint32_t ncmds;
   uint32_t sizeofcmds;
   uint32_t flags;
};

