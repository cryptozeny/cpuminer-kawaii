// 원본
// #ifdef __SSE2__
// #include "yescrypt-simd.c"
// #else
// #include "yescrypt-opt.c"
// #endif



// 테스트
#if defined(__ARM_NEON__)||defined(__ARM_NEON)
#include "yescrypt-neon.c"
#elif defined __SSE2__
#include "yescrypt-simd.c"
#else
#include "yescrypt-opt.c"
#endif
