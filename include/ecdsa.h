#ifndef _ECDSA_H__
#define _ECDSA_H__

#include <openssl/ecdsa.h>

void ecdsa_sign(EC_GROUP* group,
              const char* dgst,
              int dgst_len,
              const char* d,
              const char* k);

#endif /* _ECDSA_H__ */
