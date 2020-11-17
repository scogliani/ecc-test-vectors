#ifndef _ECDSA_H__
#define _ECDSA_H__

#include <openssl/ecdsa.h>

typedef struct
{
  const char *dgst;
  int dgst_len;
  const char *d;
  const char *k;
} Ecdsa_parameters;

#define ECDSA_TEST_VECTOR 15

/** Computes the ECDSA signature of the given hash value using
 *  the supplied private key and returns the created signature.
 *  @param group EC_GROUP object used for the ECDSA signature
 *  @param dgst pointer to the hash value
 *  @param dgst_len length of the hash value
 *  @param d The private key of the ECDSA protocol
 *  @param k The public key of the ECDSA protocol
 */
ECDSA_SIG *ecdsa_deterministic_sign(EC_GROUP const *group,
                                    const EVP_MD *(*hash)(), const char *msg,
                                    int dgst_len, const char *d, const char *k);

void ecdsa_parameters_set_values(EC_GROUP const *group, int dgst_len,
                                 Ecdsa_parameters array[ECDSA_TEST_VECTOR]);

#endif /* _ECDSA_H__ */
