#ifndef _ECDH_KAT_H__
#define _ECDH_KAT_H__

#include <openssl/ec.h>

typedef struct
{
  const char *priv;
  const char *kcx0;
  const char *kcy0;
} Ecdh_parameters;

#define ECDH_KAT_TEST_VECTOR 25

char *ecdh_kat(EC_GROUP const *group, const char *priv, const char *kcx0,
               const char *kcy0);

/** Set an array of ecdh_parameters from specific group values
 * @param array The array to set
 * @param group The group we use to set
 */
void ecdh_parameters_set_values(EC_GROUP const *group,
                                Ecdh_parameters array[ECDH_KAT_TEST_VECTOR]);

#endif /* _ECDH_KAT_H__ */
