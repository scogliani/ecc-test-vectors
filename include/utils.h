#ifndef _UTILS_H__
#define _UTILS_H__

#include <openssl/e_os.h>

#include <openssl/err.h>

#define ABORT                                              \
  do                                                       \
  {                                                        \
    fflush(stdout);                                        \
    fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
    ERR_print_errors_fp(stderr);                           \
    EXIT(1);                                               \
  } while (0)

#endif /* _UTILS_H__ */
