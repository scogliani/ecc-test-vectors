#include <string.h>
#include <stdlib.h>

#include <ecdsa.h>
#include <utils.h>
#include <mk_eckey.h>

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

/* functions to change the RAND_METHOD */
int change_rand(void);
int restore_rand(void);
int fbytes(unsigned char *buf, int num);

static RAND_METHOD fake_rand;
static const RAND_METHOD *old_rand;

int change_rand(void)
{
  /* save old rand method */
  if ((old_rand = RAND_get_rand_method()) == NULL)
    return 0;

  fake_rand.seed = old_rand->seed;
  fake_rand.cleanup = old_rand->cleanup;
  fake_rand.add = old_rand->add;
  fake_rand.status = old_rand->status;

  /* use own random function */
  fake_rand.bytes = fbytes;

  fake_rand.pseudorand = old_rand->bytes;

  /* set new RAND_METHOD */
  if (!RAND_set_rand_method(&fake_rand))
    return 0;

  return 1;
}

int restore_rand(void)
{
  if (!RAND_set_rand_method(old_rand))
    return 0;

  else
    return 1;
}

static int fbytes_counter = 0;
static const char *numbers[2];

int fbytes(unsigned char *buf, int num)
{
  int ret;
  BIGNUM *tmp = NULL;

  if (fbytes_counter >= 2)
    return 0;

  tmp = BN_new();

  if (!tmp)
    return 0;

  if (!BN_dec2bn(&tmp, numbers[fbytes_counter])) {
    BN_free(tmp);
    return 0;
  }

  fbytes_counter++;

  if (num != BN_num_bytes(tmp) || !BN_bn2bin(tmp, buf))
    ret = 0;
  else
    ret = 1;

  BN_free(tmp);
  return ret;
}

void ecdsa_sign(EC_GROUP* group,
              const char* dgst,
              int dgst_len,
              const char* d,
              const char* k)
{
  ECDSA_SIG* sign = NULL;
  EC_KEY* key = NULL;
  BIGNUM* priv;
  BIGNUM* pub;
  char* rval;
  char* sval;
  unsigned char digest[dgst_len];
  int i;
  char sub[3];

  for (sub[2] = '\0', i = 0; i < (dgst_len*2); i+=2)
  {
    memcpy(sub, &dgst[i], 2);

    digest[i/2] = (unsigned char)strtol(sub , NULL, 16);
  }

  if (!change_rand())
    ABORT;

  priv = BN_new();
  pub = BN_new();

  if (!BN_hex2bn(&priv, d))
    ABORT;

  if (!BN_hex2bn(&pub, k))
    ABORT;

  numbers[0] = BN_bn2dec(priv);
  numbers[1] = BN_bn2dec(pub);

  if (!(key = EC_KEY_new()))
    ABORT;

  if (!EC_KEY_set_group(key, group))
    ABORT;

  if (!EC_KEY_generate_key(key))
    ABORT;

  if(!(sign = ECDSA_do_sign(digest, dgst_len, key)))
    ABORT;

  if (!(rval = BN_bn2hex(sign->r)))
    ABORT;

  if (!(sval = BN_bn2hex(sign->s)))
    ABORT;

  fprintf(stdout, "r = %s\n", rval);
  fprintf(stdout, "s = %s\n\n", sval);

  if (!restore_rand())
    ABORT;

  OPENSSL_free(sval);
  OPENSSL_free(rval);
  BN_free(pub);
  BN_free(priv);
  EC_KEY_free(key);
  ECDSA_SIG_free(sign);
}
