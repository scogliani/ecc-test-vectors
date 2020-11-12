#include <openssl/ec.h>

#include <mk_eckey.h>
#include <utils.h>

static EC_KEY *set_group_key(EC_KEY *key, EC_GROUP const *group);
static void set_private_key(EC_KEY *key, const char *private_key);
static void compute_and_set_public_key(EC_KEY *key, const char *x, const char *y);

EC_KEY *set_group_key(EC_KEY *key, EC_GROUP const *group)
{

  if (!EC_KEY_set_group(key, group))
    goto err;

err:
  ERR_print_errors_fp(stderr);
  return key;
}

void set_private_key(EC_KEY *key, const char *private_key)
{
  BIGNUM *priv = NULL;

  if (!(priv = BN_new()))
    goto err;

  if (!BN_hex2bn(&priv, private_key))
    goto err;

  if (!EC_KEY_set_private_key(key, priv))
    goto err;

err:
  ERR_print_errors_fp(stderr);
  BN_clear_free(priv);
}

void compute_and_set_public_key(EC_KEY *key, const char *x, const char *y)
{
  EC_POINT *pub = NULL;
  BIGNUM *x0 = NULL;
  BIGNUM *y0 = NULL;
  BN_CTX *ctx;
  EC_GROUP const *group = EC_KEY_get0_group(key);

  if (!(ctx = BN_CTX_new()))
    goto err;

  if (!((x0 = BN_new()) && (BN_hex2bn(&x0, x))))
    goto err;

  if (!((y0 = BN_new()) && (BN_hex2bn(&y0, y))))
    goto err;

  if (!(pub = EC_POINT_new(group)))
    goto err;

  if (!EC_POINT_set_affine_coordinates_GFp(group, pub, x0, y0, ctx))
    goto err;

  if (!EC_KEY_set_public_key(key, pub))
    goto err;

err:
  ERR_print_errors_fp(stderr);
  BN_CTX_free(ctx);
  BN_free(y0);
  BN_free(x0);
  EC_POINT_free(pub);
}

EC_KEY *mk_eckey(EC_GROUP const *group, const char *private_key, const char *x,
                 const char *y)
{
  int ok = 0;

  EC_KEY *key = NULL;

  if (!(key = EC_KEY_new()))
    ABORT;

  set_group_key(key, group);
  set_private_key(key, private_key);
  compute_and_set_public_key(key, x, y);

  ok = 1;

  if (ok)
    return key;
  else if (key)
    EC_KEY_free(key);

  return NULL;
}

