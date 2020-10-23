#ifndef ECDH_KAT_H__
#define ECDH_KAT_H__

#include <openssl/ec.h>

EC_KEY *mk_eckey(EC_GROUP* grp, const char *p);

void ecdh_kat(EC_GROUP* group,
              const char* priv,
              const char* kcx0,
              const char* kcy0);

#endif /* ECDH_KAT_H__ */ 
