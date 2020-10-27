#ifndef _MK_ECKEY_H__
#define _MK_ECKEY_H__

#include <openssl/ec.h>
#include <openssl/bn.h>

/**
 * Creates an elliptic curve cryptography (y^2 = x^3 + ax + b (mod p))
 * @param kcp prime modulus p of the field GF(p)
 * @param kca a value of the equation
 * @return
 */
EC_KEY *mk_eckey(EC_GROUP* grp, const char *p);

#endif /*  */
