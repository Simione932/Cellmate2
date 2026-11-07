// The LibreSSL libcrypto.a in the curl win64-mingw bundle was built with
// large-file macros and references plain fstat64(), which this mingw-w64
// libc does not export. On Windows file sizes are 64-bit already, so plain
// _fstat64 is the right implementation.
#if defined(_WIN32)
#include <sys/stat.h>
#undef fstat64 /* _mingw_stat64.h maps this to _fstat64; we need the raw symbol */

int fstat64(int fd, struct _stat64* st) { return _fstat64(fd, st); }
#endif
