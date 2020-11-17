#ifndef _ECC_H__
#define _ECC_H__

#include <openssl/ec.h>

#define NUM_EC 6

EC_GROUP *secp192r1;
EC_GROUP *secp224r1;
EC_GROUP *secp256r1;
EC_GROUP *secp384r1;
EC_GROUP *secp521r1;
EC_GROUP *frp256v1;

void init_ecc();
void destroy_ecc();

#endif /* _ECC_H__*/
