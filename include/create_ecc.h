#ifndef _CREATE_ECC_H__
#define _CREATE_ECC_H__

#include <openssl/ec.h>

/** Creates an elliptic curve cryptography (y^2 = x^3 + ax + b (mod p))
 *  @param kcp prime modulus p of the field GF(p)
 *  @param kca a value of the equation
 *  @param kcb b value of the equation
 *  @param kcx0 x affine coordinate of a sample base point
 *  @param kcy0 y affine coordinate of a sample base point
 *  @param kcq The group order used for generating the sample point
 *  @param kci cofactor of kcq, namely kcq*kci are the points numbers of the
 *  curve
 *  @return newly created EC_GROUP object or NULL in case of an error.
 */
EC_GROUP* create_ecc(const char* kcp,
                     const char* kca,
                     const char* kcb,
                     const char* kcx0,
                     const char* kcy0,
                     const char* kcq,
                     const char* kci);

#endif /* _CREATE_ECC_H__ */
