#include <stdint.h>

#define MH_MAGIC  0xfeedface

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

#define CPU_ARCH_ABI64      (1 << 28)
#define CPU_TYPE_X86        7
#define CPU_TYPE_X86_64     (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_POWERPC    18
#define CPU_TYPE_POWERPC64  (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)

/* File types */
#define MH_OBJECT     0x1
#define MH_EXECUTE    0x2
#define MH_FVMLIB     0x3
#define MH_CORE       0x4
#define MH_PRELOAD    0x5
#define MH_DYLIB      0x6
#define MH_DYLINKER   0x7
#define MH_BUNDLE     0x8
#define MH_DYLIB_STUB 0x9
#define MH_DSYM       0xa

