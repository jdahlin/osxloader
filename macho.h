#include <stdint.h>

#define MH_MAGIC  0xfeedface

struct mach_header {
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

/* load commads */
struct load_command {
   uint32_t cmd;
   uint32_t cmdsize;
};

#define LC_SEGMENT        0x01
#define LC_SYMTAB         0x02
#define LC_SYMSEG         0x03
#define LC_THREAD         0x04
#define LC_UNIXTHREAD     0x05
#define LC_LOADFVMLIB     0x06
#define LC_IDFVMLIB       0x07
#define LC_IDENT          0x08
#define LC_FVMFILE        0x09
#define LC_PREPAGE        0x0a
#define LC_DYSYMTAB       0x0b
#define LC_LOAD_DYLIB     0x0c
#define LC_ID_DYLIB       0x0d
#define LC_LOAD_DYLINKER  0x0e
#define LC_ID_DYLINKER    0x0f
#define LC_PREBOUND_DYLIB 0x10
#define LC_ROUTINES       0x11
#define LC_SUB_FRAMEWORK  0x12
#define LC_SUB_UMBRELLA   0x13
#define LC_SUB_CLIENT     0x14
#define LC_SUB_LIBRARY    0x15
#define LC_TWOLEVEL_HINTS 0x16
#define LC_PREBIND_CKSUM  0x17
#define LC_UUID           0x1b

/* thread state */
typedef struct mach_i386_thread_state {
      unsigned int eax;
      unsigned int ebx;
      unsigned int ecx;
      unsigned int edx;
      unsigned int edi;
      unsigned int esi;
      unsigned int ebp;
      unsigned int esp;
      unsigned int ss;
      unsigned int eflags;
      unsigned int eip;
      unsigned int cs;
      unsigned int ds;
      unsigned int es;
      unsigned int fs;
      unsigned int gs;
} mach_i386_thread_state_t;

struct thread_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t flavor;
    uint32_t count;
    struct mach_i386_thread_state state;
};

