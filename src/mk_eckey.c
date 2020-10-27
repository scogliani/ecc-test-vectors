#include <mk_eckey.h>
#include <utils.h>

EC_KEY* mk_eckey(EC_GROUP* grp, const char* p)
{
  int ok = 0;
  EC_KEY* k = NULL;
  BIGNUM* priv = NULL;
  EC_POINT* pub = NULL;

  k = EC_KEY_new();
  if (!k)
    ABORT;

  priv = BN_new();
  if (!priv)
    ABORT;

  if (!EC_KEY_set_group(k, grp))
    ABORT;

  if (!BN_hex2bn(&priv, p))
    ABORT;


  if (!EC_KEY_set_private_key(k, priv))
    ABORT;

  pub = EC_POINT_new(grp);

  if (!pub)
    ABORT;

  if (!EC_POINT_mul(grp, pub, priv, NULL, NULL, NULL))
    ABORT;

  if (!EC_KEY_set_public_key(k, pub))
    ABORT;

  ok = 1;

  EC_POINT_free(pub);
  BN_clear_free(priv);

  if (ok)
    return k;
  else if (k)
    EC_KEY_free(k);

  return NULL;
}
