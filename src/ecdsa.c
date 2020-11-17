#include <stdlib.h>
#include <string.h>

#include <ecc.h>
#include <ecdsa.h>
#include <utils.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

static int change_rand(void);
static int restore_rand(void);
static int fbytes(unsigned char *buf, int num);
static void unhexlify(unsigned char *msg_hex, const char *msg);
static void digest_msg(unsigned char *digest, unsigned char *msg_hex,
                       const size_t msg_hex_size, const EVP_MD *(*hash)());

static RAND_METHOD fake_rand;
static const RAND_METHOD *old_rand;

static int fbytes_counter = 0;
static char *numbers[2];

int change_rand(void)
{
  /* save old rand method */
  if ((old_rand = RAND_get_rand_method()) == NULL)
  {
    return 0;
  }

  fake_rand.seed = old_rand->seed;
  fake_rand.cleanup = old_rand->cleanup;
  fake_rand.add = old_rand->add;
  fake_rand.status = old_rand->status;

  /* use own random function */
  fake_rand.bytes = fbytes;

  fake_rand.pseudorand = old_rand->bytes;

  /* set new RAND_METHOD */
  if (!RAND_set_rand_method(&fake_rand))
  {
    return 0;
  }

  return 1;
}

int restore_rand(void)
{
  if (!RAND_set_rand_method(old_rand))
  {
    return 0;
  }

  else
  {
    return 1;
  }
}

int fbytes(unsigned char *buf, int num)
{
  int ret;
  BIGNUM *tmp = NULL;

  if (fbytes_counter >= 2)
  {
    return 0;
  }

  tmp = BN_new();

  if (!tmp)
  {
    return 0;
  }

  if (!BN_dec2bn(&tmp, numbers[fbytes_counter]))
  {
    BN_free(tmp);
    return 0;
  }

  fbytes_counter++;

  if (num != BN_num_bytes(tmp) || !BN_bn2bin(tmp, buf))
  {
    ret = 0;
  }
  else
  {
    ret = 1;
  }

  BN_free(tmp);
  return ret;
}

void unhexlify(unsigned char *msg_hex, const char *msg)
{
  size_t i;
  char sub[3];

  for (sub[2] = '\0', i = 0; i < strlen(msg); i += 2)
  {
    memcpy(sub, &msg[i], 2);

    msg_hex[i / 2] = (unsigned char)strtol(sub, NULL, 16);
  }
}

void digest_msg(unsigned char *digest, unsigned char *msg_hex,
                const size_t msg_hex_size, const EVP_MD *(*hash)())
{
  EVP_MD_CTX md_ctx;

  EVP_MD_CTX_init(&md_ctx);
  EVP_DigestInit(&md_ctx, hash());
  EVP_DigestUpdate(&md_ctx, (const void *)msg_hex, msg_hex_size);
  EVP_DigestFinal(&md_ctx, digest, NULL);

  EVP_MD_CTX_cleanup(&md_ctx);
}

ECDSA_SIG *ecdsa_deterministic_sign(EC_GROUP const *group,
                                    const EVP_MD *(*hash)(), const char *msg,
                                    int dgst_len, const char *d, const char *k)
{
  ECDSA_SIG *sign = NULL;
  EC_KEY *key = NULL;
  BIGNUM *priv = NULL;
  BIGNUM *pub = NULL;

  unsigned char digest[dgst_len];
  const size_t msg_hex_size = strlen(msg) / 2;
  unsigned char msg_hex[msg_hex_size];

  unhexlify(msg_hex, msg);

  digest_msg(digest, msg_hex, msg_hex_size, hash);

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

  if (!(sign = ECDSA_do_sign(digest, dgst_len, key)))
    ABORT;

  if (!restore_rand())
    ABORT;

  fbytes_counter = 0;

  if (pub)
  {
    BN_free(pub);
  }
  if (priv)
  {
    BN_free(priv);
  }
  if (key)
  {
    EC_KEY_free(key);
  }

  OPENSSL_free(numbers[0]);
  OPENSSL_free(numbers[1]);

  return sign;
}

void ecdsa_parameters_set_values(EC_GROUP const *group, int dgst_len,
                                 Ecdsa_parameters array[ECDSA_TEST_VECTOR])
{
  Ecdsa_parameters ecdsa_param;

  if (group == secp224r1 && dgst_len == SHA224_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "699325d6fc8fbbb4981a6ded3c3a54ad2e4e3db8a5669201912064c"
                       "64e700c139248cdc19495df081c3fc60245b9f25fc9e301b845b3d7"
                       "03a694986e4641ae3c7e5a19e6d6edbf1d61e535f49a8fad5f4ac26"
                       "397cfec682f161a5fcd32c5e780668b0181a91955157635536a2236"
                       "7308036e2070f544ad4fff3d5122c76fad5d";
    ecdsa_param.d = "16797b5c0c7ed5461e2ff1b88e6eafa03c0f46bf072000dfc830d615";
    ecdsa_param.k = "d9a5a7328117f48b4b8dd8c17dae722e756b3ff64bd29a527137eec0";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "7de42b44db0aa8bfdcdac9add227e8f0cc7ad1d94693beb5e1d325e"
                       "5f3f85b3bd033fc25e9469a89733a65d1fa641f7e67d668e7c71d73"
                       "6233c4cba20eb83c368c506affe77946b5e2ec693798aecd7ff943c"
                       "d8fab90affddf5ad5b8d1af332e6c5fe4a2df16837700b2781e0882"
                       "1d4fbdd8373517f5b19f9e63b89cfeeeef6f";
    ecdsa_param.d = "cf020a1ff36c28511191482ed1e5259c60d383606c581948c3fbe2c5";
    ecdsa_param.k = "c780d047454824af98677cf310117e5f9e99627d02414f136aed8e83";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "af0da3adab82784909e2b3dadcecba21eced3c60d7572023dea1710"
                       "44d9a10e8ba67d31b04904541b87fff32a10ccc6580869055fec621"
                       "6a00320a28899859a6b61faba58a0bc10c2ba07ea16f214c3ddcc9f"
                       "c5622ad1253b63fe7e95227ae3c9caa9962cffc8b1c4e8260036469"
                       "d25ab0c8e3643a820b8b3a4d8d43e4b728f9";
    ecdsa_param.d = "dde6f173fa9f307d206ce46b4f02851ebce9638a989330249fd30b73";
    ecdsa_param.k = "6629366a156840477df4875cfba4f8faa809e394893e1f5525326d07";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "cfa56ae89727df6b7266f69d6636bf738f9e4f15f49c42a0123edac"
                       "4b3743f32ea52389f919ceb90575c4184897773b2f2fc5b3fcb3548"
                       "80f15c93383215d3c2551fcc1b4180a1ac0f69c969bbc306acd115c"
                       "e3976eff518540f43ad4076dbb5fbad9ce9b3234f1148b8f5e05919"
                       "2ff480fc4bcbd00d25f4d9f5ed4ba5693b6c";
    ecdsa_param.d = "aeee9071248f077590ac647794b678ad371f8e0f1e14e9fbff49671e";
    ecdsa_param.k = "1d35d027cd5a569e25c5768c48ed0c2b127c0f99cb4e52ea094fe689";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "c223c8009018321b987a615c3414d2bb15954933569ca989de32d6b"
                       "f11107bc47a330ab6d88d9b50d106cf5777d1b736b14bc48deda1bc"
                       "573a9a7dd42cd061860645306dce7a5ba8c60f135a6a21999421ce8"
                       "c4670fe7287a7e9ea3aa1e0fa82721f33e6e823957fe86e2283c89e"
                       "f92b13cd0333c4bb70865ae1919bf538ea34";
    ecdsa_param.d = "29c204b2954e1406a015020f9d6b3d7c00658298feb2d17440b2c1a4";
    ecdsa_param.k = "39547c10bb947d69f6c3af701f2528e011a1e80a6d04cc5a37466c02";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "1c27273d95182c74c100d85b5c08f4b26874c2abc87f127f304aedb"
                       "f52ef6540eba16dd664ae1e9e30ea1e66ff9cc9ab5a80b5bcbd19dd"
                       "e88a29ff10b50a6abd73388e8071306c68d0c9f6caa26b7e68de293"
                       "12be959b9f4a5481f5a2ad2070a396ed3de21096541cf58c4a13308"
                       "e08867565bf2df9d649357a83cdcf18d2cd9";
    ecdsa_param.d = "8986a97b24be042a1547642f19678de4e281a68f1e794e343dabb131";
    ecdsa_param.k = "509712f9c0f3370f6a09154159975945f0107dd1cee7327c68eaa90b";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "069ae374971627f6b8503f3aa63ab52bcf4f3fcae65b98cdbbf917a"
                       "5b08a10dc760056714db279806a8d43485320e6fee0f1e0562e077e"
                       "e270ace8d3c478d79bcdff9cf8b92fdea68421d4a276f8e62ae3793"
                       "87ae06b60af9eb3c40bd7a768aeffccdc8a08bc78ca2eca18061058"
                       "043a0e441209c5c594842838a4d9d778a053";
    ecdsa_param.d = "d9aa95e14cb34980cfddadddfa92bde1310acaff249f73ff5b09a974";
    ecdsa_param.k = "1f1739af68a3cee7c5f09e9e09d6485d9cd64cc4085bc2bc89795aaf";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "d0d5ae3e33600aa21c1606caec449eee678c87cb593594be1fbb048"
                       "cc7cfd076e5cc7132ebe290c4c014e7a517a0d5972759acfa1438d9"
                       "d2e5d236d19ac92136f6252b7e5bea7588dcba6522b6b18128f003e"
                       "cab5cb4908832fb5a375cf820f8f0e9ee870653a73dc2282f2d4562"
                       "2a2f0e85cba05c567baf1b9862b79a4b244e";
    ecdsa_param.d = "380fb6154ad3d2e755a17df1f047f84712d4ec9e47d34d4054ea29a8";
    ecdsa_param.k = "14dbdffa326ba2f3d64f79ff966d9ee6c1aba0d51e9a8e59f5686dc1";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "79b7375ae7a4f2e4adad8765d14c1540cd9979db38076c157c1837c"
                       "760ca6febbb18fd42152335929b735e1a08041bd38d315cd4c6b7dd"
                       "2729de8752f531f07fe4ddc4f1899debc0311eef0019170b58e0889"
                       "5b439ddf09fbf0aeb1e2fd35c2ef7ae402308c3637733802601dd21"
                       "8fb14c22f57870835b10818369d57d318405";
    ecdsa_param.d = "6b98ec50d6b7f7ebc3a2183ff9388f75e924243827ddded8721186e2";
    ecdsa_param.k = "ab3a41fedc77d1f96f3103cc7dce215bf45054a755cf101735fef503";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "8c7de96e6880d5b6efc19646b9d3d56490775cb3faab342e64db2e3"
                       "88c4bd9e94c4e69a63ccdb7e007a19711e69c06f106b71c983a6d97"
                       "c4589045666c6ab5ea7b5b6d096ddf6fd35b819f1506a3c37ddd409"
                       "29504f9f079c8d83820fc8493f97b2298aebe48fdb4ff472b29018f"
                       "c2b1163a22bfbb1de413e8645e871291a9f6";
    ecdsa_param.d = "8dda0ef4170bf73077d685e7709f6f747ced08eb4cde98ef06ab7bd7";
    ecdsa_param.k = "9ef6ebd178a76402968bc8ec8b257174a04fb5e2d65c1ab34ab039b9";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "c89766374c5a5ccef5823e7a9b54af835ac56afbbb517bd77bfecf3"
                       "fea876bd0cc9ea486e3d685cfe3fb05f25d9c67992cd7863c80a55c"
                       "7a263249eb3996c4698ad7381131bf3700b7b24d7ca281a100cf2b7"
                       "50e7f0f933e662a08d9f9e47d779fb03754bd20931262ff381a2fe7"
                       "d1dc94f4a0520de73fa72020494d3133ecf7";
    ecdsa_param.d = "3dbe18cd88fa49febfcb60f0369a67b2379a466d906ac46a8b8d522b";
    ecdsa_param.k = "385803b262ee2ee875838b3a645a745d2e199ae112ef73a25d68d15f";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "30f0e3b502eec5646929d48fd46aa73991d82079c7bd50a38b38ec0"
                       "bd84167c8cf5ba39bec26999e70208af9b445046cd9d20c82b7629c"
                       "a1e51bdd00daddbc35f9eb036a15ac57898642d9db09479a38cc80a"
                       "2e41e380c8a766b2d623de2de798e1eabc02234b89b85d60154460c"
                       "3bf12764f3fbf17fcccc82df516a2fbe4ecf";
    ecdsa_param.d = "c906b667f38c5135ea96c95722c713dbd125d61156a546f49ddaadc6";
    ecdsa_param.k = "b04d78d8ac40fefadb99f389a06d93f6b5b72198c1be02dbff6195f0";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "6bbb4bf987c8e5069e47c1a541b48b8a3e6d14bfd9ac6dfaa7503b6"
                       "4ab5e1a55f63e91cf5c3e703ac27ad88756dd7fb2d73b909fc15302"
                       "d0592b974d47e72e60ed339a40b34d39a49b69ea4a5d26ce86f3ca0"
                       "0a70f1cd416a6a5722e8f39d1f0e966981803d6f46dac34e4c76402"
                       "04cd0d9f1e53fc3acf30096cd00fa80b3ae9";
    ecdsa_param.d = "3456745fbd51eac9b8095cd687b112f93d1b58352dbe02c66bb9b0cc";
    ecdsa_param.k = "854b20c61bcdf7a89959dbf0985880bb14b628f01c65ef4f6446f1c1";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "05b8f8e56214d4217323f2066f974f638f0b83689fc4ed120184823"
                       "0efdc1fbca8f70359cecc921050141d3b02c2f17aa306fc2ce5fc06"
                       "e7d0f4be162fcd985a0b687b4ba09b681cb52ffe890bf5bb4a104cb"
                       "2e770c04df433013605eb8c72a09902f4246d6c22b8c191ef1b0bec"
                       "e10d5ce2744fc7345307dd1b41b6eff0ca89";
    ecdsa_param.d = "2c522af64baaca7b7a08044312f5e265ec6e09b2272f462cc705e4c3";
    ecdsa_param.k = "9267763383f8db55eed5b1ca8f4937dc2e0ca6175066dc3d4a4586af";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "e5c979f0832242b143077bce6ef146a53bb4c53abfc033473c59f3c"
                       "4095a68b7a504b609f2ab163b5f88f374f0f3bff8762278b1f1c373"
                       "23b9ed448e3de33e6443796a9ecaa466aa75175375418186c352018"
                       "a57ce874e44ae72401d5c0f401b5a51804724c10653fded9066e899"
                       "4d36a137fdeb9364601daeef09fd174dde4a";
    ecdsa_param.d = "3eff7d07edda14e8beba397accfee060dbe2a41587a703bbe0a0b912";
    ecdsa_param.k = "7bb48839d7717bab1fdde89bf4f7b4509d1c2c12510925e13655dead";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp224r1 && dgst_len == SHA256_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "2b49de971bb0f705a3fb5914eb7638d72884a6c3550667dbfdf301a"
                       "df26bde02f387fd426a31be6c9ff8bfe8690c8113c88576427f1466"
                       "508458349fc86036afcfb66448b947707e791e71f558b2bf4e7e750"
                       "7773aaf4e9af51eda95cbce0a0f752b216f8a54a045d47801ff410e"
                       "e411a1b66a516f278327df2462fb5619470e";
    ecdsa_param.d = "888fc992893bdd8aa02c80768832605d020b81ae0b25474154ec89aa";
    ecdsa_param.k = "06f7a56007825433c4c61153df1a135eee2f38ec687b492ed40d9c90";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "1fa7201d96ad4d190415f2656d1387fa886afc38e5cd18b8c60da36"
                       "7acf32c627d2c9ea19ef3f030e559fc2a21695cdbb65ddf6ba36a70"
                       "af0d3fa292a32de31da6acc6108ab2be8bd37843338f0c37c2d6264"
                       "8d3d49013edeb9e179dadf78bf885f95e712fcdfcc8a172e47c09ab"
                       "159f3a00ed7b930f628c3c48257e92fc7407";
    ecdsa_param.d = "5b5a3e186e7d5b9b0fbdfc74a05e0a3d85dc4be4c87269190c839972";
    ecdsa_param.k = "5b6f7eca2bcc5899fce41b8169d48cd57cf0c4a1b66a30a150072676";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "74715fe10748a5b98b138f390f7ca9629c584c5d6ad268fc455c8de"
                       "2e800b73fa1ea9aaee85de58baa2ce9ce68d822fc31842c6b153bae"
                       "f3a12bf6b4541f74af65430ae931a64c8b4950ad1c76b31aea8c229"
                       "b3623390e233c112586aa5907bbe419841f54f0a7d6d19c003b91dc"
                       "84bbb59b14ec477a1e9d194c137e21c75bbb";
    ecdsa_param.d = "f60b3a4d4e31c7005a3d2d0f91cb096d016a8ddb5ab10ecb2a549170";
    ecdsa_param.k = "c31150420dfb38ba8347e29add189ec3e38c14b0c541497fb90bf395";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "d10131982dd1a1d839aba383cd72855bf41061c0cb04dfa1acad318"
                       "1f240341d744ca6002b52f25fb3c63f16d050c4a4ef2c0ebf5f16ce"
                       "987558f4b9d4a5ad3c6b81b617de00e04ba32282d8bf223bfedbb32"
                       "5b741dfdc8f56fa85c65d42f05f6a1330d8cc6664ad32050dd7b9e3"
                       "993f4d6c91e5e12cbd9e82196e009ad22560";
    ecdsa_param.d = "c8fc474d3b1cba5981348de5aef0839e376f9f18e7588f1eed7c8c85";
    ecdsa_param.k = "5e5405ae9ab6164bb476c1bb021ec78480e0488736e4f8222920fbd9";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "ef9dbd90ded96ad627a0a987ab90537a3e7acc1fdfa991088e9d999"
                       "fd726e3ce1e1bd89a7df08d8c2bf51085254c89dc67bc21e8a1a93f"
                       "33a38c18c0ce3880e958ac3e3dbe8aec49f981821c4ac6812dd29fa"
                       "b3a9ebe7fbd799fb50f12021b48d1d9abca8842547b3b99befa612c"
                       "c8b4ca5f9412e0352e72ab1344a0ac2913db";
    ecdsa_param.d = "04ef5d2a45341e2ace9af8a6ebd25f6cde45453f55b7a724eb6c21f6";
    ecdsa_param.k = "ec60ea6f3d6b74d102e5574182566b7e79a69699a307fee70a2d0d22";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "4cc91f744ac858d3577e48813219aa3538dd813b186b42d1e621837"
                       "6f07cc1cc448ddd6b37240e98bf953f49cf54d65c12878b33c0bf6e"
                       "b1c60254f0b6fa974f847e53abc56773eef6f29885dfc619e6a48fc"
                       "15a667ca94001a0c945b6357a53221b0f4b266181456b0d2d25e907"
                       "08777f1a6f85971c00140c631c1991e0fd06";
    ecdsa_param.d = "35d4bbe77d149812339e85c79483cb270bdac56bbf30b5ef3d1f4d39";
    ecdsa_param.k = "751869c1d0e79eb30aae8fbfb6d97bfa332123fd6b6c72c9cd3c1796";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "58f43cc1924de4bc5867664adbc9d26b4f096a43aca47c27c52851b"
                       "006dc2a658919ef9ce5b5ac48372703be15ac51631c2bd84b88f479"
                       "f113b0569a9a09e230ec1e8e573474c6075284d3e57d973829af353"
                       "25d9e7dab4a5f9b065155bbcaff3642a82ef4c9b9e127d3575c0507"
                       "21653da3b087d3fa394192897a5519527d19";
    ecdsa_param.d = "2c291a393281b75264c9b8817af684fa86a1cdc900822f74039dc5d6";
    ecdsa_param.k = "e2a860416229dfd3f5a5cc92344ca015093a543943a0d8f73bf2b2fd";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "113a2806b052fde683ee09453098e402204155afb3776fd1cad3a91"
                       "03421d327eab8f9ec0dd050ffcc83f93b34ea707705fabeccfe43ab"
                       "1a71c95298fd3ec769d99ead1066950eee677d225816e0faad19cf6"
                       "9e1b35d16771689e2092cafe16d7c0dd7b0db73fffb8d0f3eaed830"
                       "04dd21e753530ec939c89ba25578fa5f785b";
    ecdsa_param.d = "831ea25dbeda33d272a1382c5def0e83929170ab06a629eed6ee244b";
    ecdsa_param.k = "6be6dd9f6a083915ccba54626caf12d246d3aece0a7eda7d8d85599c";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "64cbfc8f2e2149a31b3e8a80c4a552f6c62aaeb7990b6e0ee55500a"
                       "9d17be04213406578caf315951086dff5c2af3b5ce17d425d185101"
                       "ef26f86396ba3a129a4f3f8e2dd595f59efb6c0f5c2dcc394569d72"
                       "68695e9ac7daa84203f1f1895f1f9e4b514a5c9cd23baa634547101"
                       "44fe735ad9b8f42d8c43267aa434a26d7e5f";
    ecdsa_param.d = "70f74c7324ef137318b610ead8ddc5b964e0eed3750b20612fc2e67b";
    ecdsa_param.k = "8e984864f86f7a2a73f3edda17dbccd13fac8fa4b872814abf223b1b";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "a10a11c8e30fff118d371daf824f16c08200b83ea059436466a4611"
                       "ccac93b2dea2de8c1006f946196aef7fe9b0c251a391b0340f21797"
                       "798278b412ff2b53842eec6450728e2bca062f8337a2c204b9ea04f"
                       "f660cd4d4db559f2f11c4d8ef199021339fcc82396f7a93926cf5f2"
                       "47e37d8067fe50692de54f102bd5ab51925c";
    ecdsa_param.d = "026be5789886d25039c11d7d58a11a6e1d52cb1d5657561f2165b8a8";
    ecdsa_param.k = "0128b8e3f50731eb5fcc223517fc0cf6b96cd1d2807eb4524bc46f77";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "b3f720bf566ffa369259f4361959ae0641d2755ec264a4c4349981d"
                       "f2b02563275b2b9adb5aee47f7a456760a971991ffed6b17809bb96"
                       "94138d1677fa916123795239353158fc6b22d10f20d26f5d2dcd8c5"
                       "6c44373eea5b93067dba2d7c5318dac2e9e8714873cb1b37f58c011"
                       "fd14fa1e535554efe05f468bfc8e11cd8b99";
    ecdsa_param.d = "e79c18d935c2839644762867aa793201f96a3cde080c5968412ce784";
    ecdsa_param.k = "7abedab1d36f4f0959a03d968b27dd5708223b66e0fc48594d827361";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "0a398a46df7ccc48d1e7833f8bbc67100f1ef77a62dc78bbc115b2a"
                       "662f9591fbaaa91ad3d788e2fdd1b3164e45293d4f5686c15129690"
                       "1768028ac80ded4bf89c647ad35f0c7c4cb318c0c757c1d83c44d85"
                       "0e5fd4677281b3f13b1ee54de79c8c042813f9d3312dcc6111a6829"
                       "9cb7e829557d7f3d96e702f65aefc6499415";
    ecdsa_param.d = "0d087f9d1f8ae29c9cf791490efc4a5789a9d52038c4b1d22494ad8c";
    ecdsa_param.k = "557d0e3995dc6377b3911546dd7aeaeec62a6d8f2af6a274382fc37f";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "8c33616821a6038b448d8918668977fcf1ef5aa0cf7c341837b39bb"
                       "cc9bca875a3757f4b392630e9995b9bbe4eb66978b877586adaa02f"
                       "99d2344dae082a7603351d8ffcfca081ab403cd0acb90d078dd1d07"
                       "89c2eb3185c62bff2d9f04cd38e509e3b83c12ed0a5c6808fc42f7b"
                       "a5b06acdc496c8ad9be648ee6a4505f8560f";
    ecdsa_param.d = "0830aebb6577d3a3be3ba54a4501c987b0e0bb593267b9bbadb66583";
    ecdsa_param.k = "e4f4a3280574c704c2fde47ca81ec883d27f2c5a961a294db7cda9d2";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "94d56535fd4edfe67a0daa6579f9d53bf6b7b8830ae2aeb62892ff5"
                       "9f18756ddf2811b449c7d20d65d54f8507de4e7c50eaa0848306378"
                       "12aa4b250a4d61ab67845be36e4a41cdc0a70f8d6e3a63d4514f0dc"
                       "197e6486015046a316153d5f3a3a4a0ae1ed7ea5fa55e12e73d3333"
                       "33685c02e0eb636234ea7e6d4b76b4b76b5a";
    ecdsa_param.d = "2acc9b97e625263e8e4cd164302c7d1e078bfcdd706111a13ccda5b2";
    ecdsa_param.k = "e401fa80f96480d437ed4f61a783888062ec33d530b188fd48016a6d";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "5d8ebdf9eb28b47bdafaa36bf0b66a9eaf99b6c83959da4f2b1151b"
                       "4f4ecd28fb115a64c0cb9491093a7e9b9c53ec423e4c72e7765bb9c"
                       "818da0e8c428667e44474a71db4867130c77c40bfd8544b2d7b9d64"
                       "64d2b8e6a48482153256a32437c3a747231f51134dd14c703407e31"
                       "146a6fcde23bededcf16950486e90ca69ac0";
    ecdsa_param.d = "f4e873d4fb944fb52323406f933815092b7672221de4d1c45917f3fc";
    ecdsa_param.k = "5d1476c682a64162fd2fdc82696fc8cab1469a86f707ea2757416e40";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp224r1 && dgst_len == SHA384_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "25e4416695f77551fdce276355528ccf1ddc2483821c5d22d751d50"
                       "111ca2fadc6593b52c74f4b5957494f1df25b0b2f86950d0d19229e"
                       "c6506fee8581d2dd09d48418b146ff16bd84a17ca0dc83b1888eb40"
                       "7376da6c8a88fa1e60b8c2a2471dfde4b3996ef673d5bde3d70c434"
                       "dc9f2488e9de16ae657d29e5e59ec922a1ec";
    ecdsa_param.d = "62c572ee0d6f81b27e591d788bfc2f42b5105d2663078dfb58069ebd";
    ecdsa_param.k = "0f0bb1e428bcdebf4dc62a5278068efc0f8ce75f89e89b3630f102b2";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "9164d633a553deccf3cbd2effccf1387fa3177cd28c95d94a7d1a3e"
                       "159c5e5c027758cc26493301b2f4d141d8d07a5fe5fead987ce5f30"
                       "abeafcb48c302afc6c2309f0e93d9b6818cbb6972d222cb7b01302d"
                       "fe202ae83b89f53150ae4a0e2b8fc0fd1091f19b4ab2e6ab213ab32"
                       "2d04f2c5f57113bfad3c5675227237abf773";
    ecdsa_param.d = "e2f86bf73ba9336fa023343060f038e9ad41e5fe868e9f80574619a3";
    ecdsa_param.k = "35724ac043e3b44b73b5a7919cf675190306d26aa67c27c28c873534";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "019df05929321ecea7ee1de4f412aba1c8d3c24437db04b194a68a0"
                       "a59dd871be10bd3a4be6edf551350ea49fc7155a4d887e122148629"
                       "1abe77a30633a4c4f7868fe2df24311cba0c73804883954460e1223"
                       "87ed414111ff96ff1aebac8b6a6491d8a0d16e48a63bf3d027c0f68"
                       "ee4a4b234d73b412196706af8ea022b4dcef";
    ecdsa_param.d = "b0a203438e2586d7575bc417a4a798e47abc22aa3955b58fc2789f17";
    ecdsa_param.k = "408e9c8b1f33136d6ddb93ff3a498bc09d4eee99bf69cdd5af0aa5a2";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "5d09d2b1d3fa6e12c10d8b26dc9aabc8dc02bd06e63ff33f8bb91ed"
                       "e4b8694592a69e4ed4cdf6820069e2b9c7803658949e877ffe23bf9"
                       "0bcf5ce1409c06c71d86885a94048b05ac0ec9db193e489a5a2bfa3"
                       "67caf6aa8ecdb032be366174343f6875d2fe1785e8d77334f5f469c"
                       "ec64998e08d3303e5c9a1923b34fdc105d65";
    ecdsa_param.d = "efcfa50fad6fb2065f9a55f28c0c42fa24c809ccb19b6fc6d8ffb085";
    ecdsa_param.k = "d1eea821f286eae6ebc1f61b08f9ad4323a3787e94af4c32cd31351b";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "50f6dfc81c6cf189e0a310f992907fe93356cee9dea9a41c7671a8d"
                       "af3f4cfe0c459ce6122c1e731dbf7593419d7114cb73b46956158a9"
                       "82c5d52c72f43f0f822046093c69aeff1f7e4cd8af00ba655c5baa2"
                       "e7b6a400b4be1f6fd51b3e4cfb35a69c80a28c5cafb771b6c2e52e0"
                       "aeef0e3fd045e8d40745f3f8b74fd969f816";
    ecdsa_param.d = "61a17816937987764cdc064dc7b5b4f5b16db1023acdfe25902957dd";
    ecdsa_param.k = "44b1fdec2629f9075f89c134ac28ff19bfddaa9db02a5d7f853582b4";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "e90129ac6672c85bb7b6b18e9dc199c96c81fd65034b53c77818364"
                       "d512366fb9cd1bc7c82404c451e561fc1ed916c0948f6ac561b33a1"
                       "ccca093f07684b8c2bafa9e966377bd208556018a5bafb9edcecf70"
                       "498c7140fe9c8cf3ad8b8c3b0aa489df797944465047465415bb0e2"
                       "4333235fcdd59a98829a3941eaaf62033e82";
    ecdsa_param.d = "79d5367314ec664aa0f6ca36f95549502a05bf8400bf532d669fab8d";
    ecdsa_param.k = "da529c52f5cc1f435d873109cd991d6cd7e1631d9ff1dd9521dd5db6";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "3c9a483c9bee33b601549c592a82e95b4319b1e74b777877f0971bc"
                       "b4273716b268e8f99f876e42f942f4cf08284896bbc1ffbf094ac09"
                       "56c3cedfc3580cffa8c74fc6db29a371f2da2d05edb9185ece741fe"
                       "0d3fabfe9d5b4d373755ebed13dc6840cfa3283b9ea46ec8b95c434"
                       "f253ae86998182e9cc0e95ee64f323fc74b0";
    ecdsa_param.d = "1320eedad4745121793a7eaf732b0b4498f7cb456cac8cf45a1f66f0";
    ecdsa_param.k = "66ed8d8934633f4125f593cf1b1d3745c4db1f15dde60cf46ca1c7f2";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "bfc073fdda63c5fccaa0ca8770c293e8154e7aec56128bbac4fdbd5"
                       "41d602216ebf7ca1e02b514d6e396f20683802ba3f334310a922657"
                       "6926e3bb19ceee27738d13377cbafeb09d091043501702a07aa31d1"
                       "f29d50ddc55adcf16ffd40578e734a4e6cb6535f26ad48e0c62ad90"
                       "e79720000e87d419e92dca3e11f943655b03";
    ecdsa_param.d = "e18821329447d3f65ba7279e96bd4624ffa1b32b90f6e8331b1e876d";
    ecdsa_param.k = "a4c1eb402a2fb3af26e0e14a3d2fc8ed3bc1a8b2475270356a79fdd3";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "08079955d1a1f33728128c73673ec9f21a6ce138dcab5adc4dc068e"
                       "6ab57314b9fbd8b013123b2fdafa9524fbdd0288777a233de8055cc"
                       "cfad83046ada6a19f01c47817496667bba8fc8b9456fc0e044a562d"
                       "931dab1adcb66af8b66325bdf28d83ded3e2937958ccd19da540d70"
                       "ef2c189f55a506c9c0d63406394c5bd3823b";
    ecdsa_param.d = "f73e030d5a696b358986d3efaca121cf71f775f8835a21e6135145d7";
    ecdsa_param.k = "e3cc786c1288ea567836c51d6d69dd0cab5c015987d936ccc3a4beb3";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "23900b768f6cd42b8a8df0dcbc9cb5daec8de36b9d5c619adcc1ba2"
                       "b649103d5af123746cdf19c3fd0665a6fb9338156182aa06181e3c6"
                       "e37ce56979612af2927440424f89cef43fc754854b8a5c43370808c"
                       "f5f9929cf47712512ce2f8a2a20d2e9f568c2848b27dfbe09142843"
                       "c83905ffa5da3b15501761b03dbc2c5398b6";
    ecdsa_param.d = "7a0789323f8741c157a1753ae165ecaf8e8b03a60561f8b80cee467c";
    ecdsa_param.k = "d169f04f05b60c625cda864d187938863964dab7bb3b9dfc04b05519";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "1eb28c0bcdd18f73e347f957ece15b4cc83a771b0877e1feaac38e2"
                       "4028fb38ccea8b54ee017dc7c3d5a1327bc6f40b294aa65d7dc487f"
                       "278846cd101ee84202f14b38aa2c275046aa2577f65ebaea41cd383"
                       "e8def2fd0b4444dcf426fa75c4082cd7fa035cdb1e0d34a3c79d421"
                       "30f5b0273eae75bc701dda3aebe7358f41b5";
    ecdsa_param.d = "78e795d0edb11fd9e28dc26b21e751aa89bea0d87932ef11c95c0e18";
    ecdsa_param.k = "36f7c0f76808b826a0a974a1fd6e155e00a73f1d34674a8f88be405a";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "efab51855407438fd5c250670366bca3c026ecec4a59394f00d8a4b"
                       "51746d0c4564366656d507e3e13e62fe7abeb976b8859895848dbae"
                       "cf6582f1898ea06f00d4247702ed9721bd375aa83ae4c67c2eaa6e0"
                       "80777ea5ecf2cf787d785389560ac91cf63a52f0373c3185e18a3b8"
                       "a466e21b61a239f1b77624eb1acacc76c4e1";
    ecdsa_param.d = "bee02d8bc5bffb3fd3b4c9d6f686409f02662d10150d1e58d689966a";
    ecdsa_param.k = "59f1450d857b40e5552a4b8cd4ab0df2f01716635d172c1106840f21";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "31c29ca10279a417f0cc9b1382cf54dbfdfc89f2e6ef08c403c11f5"
                       "80cbf8674b141ed1a417563282d99a55fc616d836421cde9424815c"
                       "95e7fb7668bf3f137b29937f14882d74e034b732d78d91af7721aac"
                       "4950734f5fa5d4b4d35534974f8cab6d2e6dca75ddb57e99148c8a5"
                       "9df9fc5bcd723e546e8356f671cf2f65640a";
    ecdsa_param.d = "dc0ddf6e501418bb8eafc5d7ccc143369e2aa441df8fc57d5f94a738";
    ecdsa_param.k = "ff0e5cae2671db7a1b90e22c63e7570bdd27352d45bac31e338debe0";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "8db476f92e332519c1a0ece5d8deded6efbd2d8e8784eea0a6b4c3b"
                       "4296c35f5f8de4317e5c1627b91fb1973fee86c06e4992aa5a20cb7"
                       "475c8808ff1da354d07a488dffa7838c6ec1e3f99e3acba831f27be"
                       "e8434eeda3eb36d0c6df3658883cd40068b1bed841310f6eb38d4a3"
                       "d07d85848770ff7933c054cd8b34662660b1";
    ecdsa_param.d = "229d89b2fcf8441ffc95ebb2ac2ef156e25825782044b2b8bd6a3e01";
    ecdsa_param.k = "3b18ca6ec8e8e255ac88f64302745ca0b73ff94b2b2d48be95b4aaee";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "fcb272c828fe8fd3c6f8de9410c7b6e2b36717c1b0e5e359e9109bd"
                       "7fc378978aa98182a9d99961898ed88999b050d3b64d1457d7a899d"
                       "6d273b9f4dde2aafa36d76329d62509043c338f265fc4c7d938459b"
                       "7fa3b230a9f6cb632b61489546bb4181a5ad7f0d7369b8caced48eb"
                       "374b075b2b325bc86add0f3b680cd9e80acd";
    ecdsa_param.d = "97d747068147c0393a0bb5c159e2c9f1bd538f6204823294883abe28";
    ecdsa_param.k = "c1a2ec1ef16cfd5107c892790daefbed061be78bd8576696b60f64d5";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp224r1 && dgst_len == SHA512_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "7522492bdb916a597b8121f3e5c273b1d2800ef8c1db4f7dcbae633"
                       "b60d7da5193ba53a63d7a377b351897c3b24903ae1cd1994211b259"
                       "be3e6ae2cbc8970e4957fdf782c7d1bc7a91c80c8ef65468d4ef354"
                       "28f26e2940ae8b0bd9b8074236bf6c00d0ebe83f9ddb2ade0f83513"
                       "8d39f33b59f244e0037c171f1ba7045a96f5";
    ecdsa_param.d = "ba5374541c13597bded6880849184a593d69d3d4f0b1cb4d0919cbd6";
    ecdsa_param.k = "187ed1f45c466cbafcd4b9577fb222408c011225dcccfd20f08b8d89";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "61097114ff855c3e34a62d9b853f8982d35f29cfa4a89893badbca7"
                       "849e5fb437a1a38d6451bf0ca5a0d528e352b8e4b57f2ea359a7fc8"
                       "841d49dd3e570f9b016f14156b0bbc4be822e260bd147ec08145496"
                       "9e11cb0034b7450ef4deb7ed6edb977e2f4ed60121aa095fb0ab402"
                       "40dc329ecc917f5c64b4410612af065ee9dd";
    ecdsa_param.d = "1e27187134d0a63542adf4665fba22f00cfc7b0a1e02effe913ceedc";
    ecdsa_param.k = "34cb597deae9a3b1cada937abcd247161b19b2b336b20e2e42ae01f1";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "dd09ae6c982bb1440ca175a87766fefeacc49393ff797c446200662"
                       "744f37a6e30c5d33ba70cbd8f12277fd6cc0704c17478bbab2a3047"
                       "469e9618e3c340a9c8caaff5ce7c8a4d90ecae6a9b84b813419dec1"
                       "4460298e7521c9b7fdb7a2089328005bd51d57f92a1bcbeecd34aa4"
                       "0482b549e006bbf6c4ce66d34a22dda4e0e0";
    ecdsa_param.d = "0905b40e6c29bfcbf55e04266f68f10ca8d3905001d68bb61a27749b";
    ecdsa_param.k = "dc82840d147f893497a82f023d7d2cbf0a3a5b2ac6cc1b9b23e504be";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "37a73e2774d3b274db426c89b945696daa96035031f72cea01894b2"
                       "4508c7f81961ec254d36ed6a0f448e11cf7950af769dc6cd2c47e52"
                       "c6caf0ea92c270974f0214b4db436c36a60fb722060a6bb544462a8"
                       "2e1714f5906ec32886f7d59ebf289541c3a00ec1e004892ef2b1286"
                       "a0194f55d083c6ec92c64b8fd1452e1c68ba";
    ecdsa_param.d = "afbaede5d75e4f241dd5b53220f3f5b9c1aa1d5d298e2d43236452dc";
    ecdsa_param.k = "0fbbe7b40136c81a8fb894498d5502157a1cf5a89d0643de92cd38f6";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "9dc2046ffdc6804544db964481abe5d2d276a2a9eeec4c7ad40215b"
                       "1de23561d402db69bd0f6eec2254711eea4487c64d9a6b62c3ebaf5"
                       "ffa8db6e7e3a6e17154d126967a47a853a6f8339bdca9be306a13c7"
                       "f992ded7619b0da59909a49b1e0930360e05b47f18628a36d69b2f8"
                       "7f2bfddd6a5d4a72f84dc76dbdd43f3a6a35";
    ecdsa_param.d = "950b07b0c2b7539a21b5135bfede214733f2e009647d38d8b21d760c";
    ecdsa_param.k = "83e110d0d1e700d2f36543028737d2a2f1474aa3b4b28998a39e4793";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "d9c6847fce688c5e7525a1098b545cb6c15dcd21a02761fc82fc664"
                       "372a667390680135f91c01a2fa5430c634b1a6d1cd6002d8aa021e7"
                       "bf5956a7901c2f81bc25d502ba5f55a55f30c0323dc68205cbefec0"
                       "538e68654e7b327ac1743641896c3e740d8f66f400902b304eafaa4"
                       "e0d8cffae140536f0922444cc3216a675697";
    ecdsa_param.d = "015bd9f5dfef393b431c3c7fced24385d861ccb563542574a5d2a9bc";
    ecdsa_param.k = "e2374350f47c08f3c1359d4edf87e61d1ba4e7dd1540d8d9062efa79";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "69df8a01b66f04930efd2012ff2243874f256ca8758145d2a9e4ecc"
                       "84d0dbdbd0dc494ae06db0ccbe819918137c90957114558580d6623"
                       "efbafdd342b38dad9f08708084d32f874fba04782ce26aaab78de21"
                       "02ad171f8a8f2b30b5bd3d55fdac5fa3acd6f7def7e61c253393857"
                       "2b331ba6d1c02bd74bfdbf7337ade8f4a190";
    ecdsa_param.d = "0a3c259df933247445acffb6d8265b601d597fb9997dc2a1eb4deef4";
    ecdsa_param.k = "8bf5859665b6a23e6b05a311580f60187ba1c4ae89e44877fb48af66";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "927524982b8d60777c1105c86fac05f634abf58c73f84fb95d81ba0"
                       "b86e1e43592c4fcad2e395a40fbe7005697d86088e2fb3bb7287eb3"
                       "f917d4f2dc281f5cbe65d05b4f9623bca849b10a03beca6aa2056a1"
                       "2ebb91cf257ac448c5e9a78f8349a6a29b17c8978bef43a443cbb8a"
                       "149eb23f794844fc41693f2dbb97181444be";
    ecdsa_param.d = "a1c8ef463f9e7e3dd63e677412f87cf9ea4ac9a6a2dae629da5b9916";
    ecdsa_param.k = "82f55a25d3ed6e47c22a6eed0fa52ed0818b87d6ea7950281dfefc09";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "5f9042283561e7f19a436d01c7ef5a950a6d77ede5629cd7e43c0a5"
                       "d58e8c5673c37945a453291d12938253c71dbe12c8b022ba7276eda"
                       "6be034ef5ec1ec77dbd1e08f0d7b8e7725b7ec671c075e008a20f77"
                       "f4ab266f97079b0aa6337df59a33b881954084057b21f294dd14bcb"
                       "0869a4a6f1f597955ec7bf9d19bb3537a66a";
    ecdsa_param.d = "fa511dbf6fef7e5e9c73e4555eb75d435f7884322d9faf5d78cacc0b";
    ecdsa_param.k = "a37d665fe4314aa4cd03eb8e6a1f366b43e11fdb419c96b48f787b62";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "c2ae5573d3bf396523bfb703db8502fd0760cd1be528f6ddbfb95aa"
                       "d399e0b19f3bd9e0fabdb05d49e3f893dffec5b627c9c2f7ad5f32e"
                       "92e4e27a38cb5c28657657377fdfa1b66cd7ac3d15c6d49df92d284"
                       "db99f69744f37dc7cb4e7d52920fdb200a7942623a7057ba82e467d"
                       "cccaa5da416b48510d8364446a6a5e2a5aa8";
    ecdsa_param.d = "a58bd53646400a646f0e4208320dc679a9664d1c6bfb27fdc8eac7ea";
    ecdsa_param.k = "42c5b6f87d3bb1ed74f5ee8398d8f8c61e9e50ffa7a1da12d39893f9";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "03c1a1cd30a039d0dcb22fee2450a7fa79495a0d0f4f43d2de4d75b"
                       "ce003c0334a8860f5c164dbd94888a9f751235a3e570d31070e3e12"
                       "93a7be616af7176600585d36ac013600157d2569d491da4b8a3bf36"
                       "30c26e0b9925412189f50b0ae6f04c86477932e2ecd8c3546106ae1"
                       "ebc684cc3adb27ed665eddece886adea4ce3";
    ecdsa_param.d = "64bd4452b572cc95510ac2e572f41136299ff17f6e8448f4ffb571d0";
    ecdsa_param.k = "eaf76ee4d7e00d13d8a6d03dffd07ad9a8bb6dc8176c9f93059b1b7f";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "888f6d9bc7c86c0079fbfd42d8c08d6958f40f6e570fb0b1f03d2f8"
                       "f8a63df4fcc87b379a222cf835820a999d34996e08961f13b86b075"
                       "e7fd1c303cd3baa44de42168561589012f7e5300da4f8bdf470c071"
                       "19a5d9f7ba7293568cd7c6a1b7fc1e41cda40bed7d46e5a28af67ae"
                       "2aabfefe67a86a1c601e6f5ee543e09bd7b6";
    ecdsa_param.d = "7f3edb710df9d982f486233d0c176aa88f5a0ee81efa9b8145020294";
    ecdsa_param.k = "94db7ef9a232593091eb9a74f289529c7e0d7fef21f80b3c8556b75e";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "48453340f1317769e6ee6e103153714365731163dc18f84e9f2fa4b"
                       "120f9c5a9645ee2f9b66c84c26d95912b422b009b64af96aa418b24"
                       "27a4209f2e7513ba8e43ec8cf20b34e7529b22eb1199545afe9a9f7"
                       "d9bcb320aec9ee0162f91c0d1dd9674c9c284f25199c5e109f6f84d"
                       "7ed0d269cc6413edb81bc2c83e37d644d8b9";
    ecdsa_param.d = "b569f8296ff1d9cc01fffd9919016e5730c1858bdb7b99527153751a";
    ecdsa_param.k = "ae61523866a8f43e6cdd42ba27a34ed06527e8a5842901a64c393f76";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "4bdfd3b91d83108409ad765b256e0c9b9937ecf647f8e6f9fc807e2"
                       "e72af8246178b3fe046b4ea10170450d71a4eec790ecb05f03d7077"
                       "341de26c4db7eeae24d55c9a9093e837dfdb38168fe8230cb960582"
                       "5a1282fecd741989bfcdb34678fe077477927f66bd26d003e5dda22"
                       "043341a14dd31841ba483ad5ce2701e0f68e";
    ecdsa_param.d = "41a4dd8eee39232b728516e2f21e66011e7426a6b25986c3ffa237e4";
    ecdsa_param.k = "827d4999da81fa920c8492ccc1e2d5cdafed9754cf7382a859952071";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "e6cdee8558bc1eacc24e82f0624ce8d02cc8d925b4dd3dec3a72f4a"
                       "4e0fb76076bfa3ef2e2c33bdd7c27b322bdc09bbfee8fe46f75dbd7"
                       "bbd2af09690b7137943efe21706e0a1b6d3089540fc58d85ddb55ea"
                       "836616db573e36c521be008893f40a0a7c349602cc178ea43be59d3"
                       "1ec6449e7ff2c5379379f7d7645134df1bc3";
    ecdsa_param.d = "67fa50569257c8cc89ac0325db4902003a62f30b917f53e4035a7e04";
    ecdsa_param.k = "557cb45fd3a30b3bdbf08c56eabbd4478736024aaa52bf8448096453";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp256r1 && dgst_len == SHA224_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e77"
                       "7b75a8e77a77bb26e5733179d58ef9bc8a4e8b6971aef2539f77ab0"
                       "963a3415bbd6258339bd1bf55de65db520c63f5b8eab3d55debd05e"
                       "9494212170f5d65b3286b8b668705b1e2b2b5568610617abb51d2dd"
                       "0cb450ef59df4b907da90cfa7b268de8c4c2";
    ecdsa_param.d =
        "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590";
    ecdsa_param.k =
        "58f741771620bdc428e91a32d86d230873e9140336fcfb1e122892ee1d501bdc";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "9155e91fd9155eeed15afd83487ea1a3af04c5998b77c0fe8c43dcc"
                       "479440a8a9a89efe883d9385cb9edfde10b43bce61fb63669935ad3"
                       "9419cf29ef3a936931733bfc2378e253e73b7ae9a3ec7a6a7932ab1"
                       "0f1e5b94d05160c053988f3bdc9167155d069337d42c9a7056619ef"
                       "c031fa5ec7310d29bd28980b1e3559757578";
    ecdsa_param.d =
        "90c5386100b137a75b0bb495002b28697a451add2f1f22cb65f735e8aaeace98";
    ecdsa_param.k =
        "36f853b5c54b1ec61588c9c6137eb56e7a708f09c57513093e4ecf6d739900e5";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "b242a7586a1383368a33c88264889adfa3be45422fbef4a2df4e3c5"
                       "325a9c7757017e0d5cf4bbf4de7f99d189f81f1fd2f0dd645574d1e"
                       "b0d547eead9375677819297c1abe62526ae29fc54cdd11bfe17714f"
                       "2fbd2d0d0e8d297ff98535980482dd5c1ebdc5a7274aabf1382c9f2"
                       "315ca61391e3943856e4c5e616c2f1f7be0d";
    ecdsa_param.d =
        "a3a43cece9c1abeff81099fb344d01f7d8df66447b95a667ee368f924bccf870";
    ecdsa_param.k =
        "a0d9a7a245bd9b9aa86cecb89341c9de2e4f9b5d095a8150826c7ba7fb3e7df7";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "b64005da76b24715880af94dba379acc25a047b06066c9bedc8f17b"
                       "8c74e74f4fc720d9f4ef0e2a659e0756931c080587ebdcd0f85e819"
                       "aea6dacb327a9d96496da53ea21aef3b2e793a9c0def5196acec998"
                       "91f46ead78a85bc7ab644765781d3543da9fbf9fec916dca975ef3b"
                       "4271e50ecc68bf79b2d8935e2b25fc063358";
    ecdsa_param.d =
        "7bbc8ff13f6f921f21e949b224c16b7176c5984d312b671cf6c2e4841135fc7f";
    ecdsa_param.k =
        "21c942f3b487accbf7fadc1c4b7a6c7567ce876c195022459fa1ebf6d04ffbaa";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "fe6e1ea477640655eaa1f6e3352d4bce53eb3d95424df7f238e93d8"
                       "531da8f36bc35fa6be4bf5a6a382e06e855139eb617a9cc9376b4da"
                       "facbd80876343b12628619d7cbe1bff6757e3706111ed53898c0219"
                       "823adbc044eaf8c6ad449df8f6aab9d444dadb5c3380eec0d91694d"
                       "f5fc4b30280d4b87d27e67ae58a1df828963";
    ecdsa_param.d =
        "daf5ec7a4eebc20d9485796c355b4a65ad254fe19b998d0507e91ea24135f45d";
    ecdsa_param.k =
        "343251dffa56e6a612fec7b078f9c3819eab402a72686b894a47a08fd97e6c23";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "907c0c00dc080a688548957b5b8b1f33ba378de1368023dcad43242"
                       "411f554eb7d392d3e5c1668fad3944ff9634105343d83b8c85d2a98"
                       "8da5f5dc60ee0518327caed6dd5cf4e9bc6222deb46d00abde745f9"
                       "b71d6e7aee6c7fdfc9ed053f2c0b611d4c6863088bd012ea9810ee9"
                       "4f8e58905970ebd07353f1f409a371ed03e3";
    ecdsa_param.d =
        "8729a8396f262dabd991aa404cc1753581cea405f0d19222a0b3f210de8ee3c5";
    ecdsa_param.k =
        "6de9e21f0b2cacc1762b3558fd44d3cf156b85dbef430dd28d59713bfb9cfa0b";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "771c4d7bce05610a3e71b272096b57f0d1efcce33a1cb4f714d6ebc"
                       "0865b2773ec5eedc25fae81dee1d256474dbd9676623614c150916e"
                       "6ed92ce4430b26037d28fa5252ef6b10c09dc2f7ee5a36a1ea7897b"
                       "69f389d9f5075e271d92f4eb97b148f3abcb1e5be0b4feb8278613d"
                       "18abf6da60bfe448238aa04d7f11b71f44c5";
    ecdsa_param.d =
        "f1b62413935fc589ad2280f6892599ad994dae8ca3655ed4f7318cc89b61aa96";
    ecdsa_param.k =
        "7a33eeb9f469afd55de2fb786847a1d3e7797929305c0f90d953b6f143bb8fc6";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "a3b2825235718fc679b942e8ac38fb4f54415a213c65875b5453d18"
                       "ca012320ddfbbc58b991eaebadfc2d1a28d4f0cd82652b12e4d5bfd"
                       "a89eda3be12ac52188e38e8cce32a264a300c0e463631f525ae5013"
                       "48594f980392c76b4a12ddc88e5ca086cb8685d03895919a8627725"
                       "a3e00c4728e2b7c6f6a14fc342b2937fc3dd";
    ecdsa_param.d =
        "4caaa26f93f009682bbba6db6b265aec17b7ec1542bda458e8550b9e68eed18d";
    ecdsa_param.k =
        "c0d37142dc8b0d614fad20c4d35af6eb819e259e513ddeac1e1c273e7e1dc1bb";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "3e6e2a9bffd729ee5d4807849cd4250021d8184cda723df6ab0e5c9"
                       "39d39237c8e58af9d869fe62d3c97b3298a99e891e5e11aa68b11a0"
                       "87573a40a3e83c7965e7910d72f81cad0f42accc5c25a4fd3cdd8ce"
                       "e63757bbbfbdae98be2bc867d3bcb1333c4632cb0a55dffeb77d8b1"
                       "19c466cd889ec468454fabe6fbee7102deaf";
    ecdsa_param.d =
        "7af4b150bb7167cb68037f280d0823ce5320c01a92b1b56ee1b88547481b1de9";
    ecdsa_param.k =
        "98edd59fafbcaee5f64e84eb5ed59fff45d14aabada47cee2fa674377173627a";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "52e5c308e70329a17c71eaedb66bbee303c8ec48a6f1a2efb235d30"
                       "8563cd58553d434e12f353227a9ea28608ec9c820ed83c95124e7a8"
                       "86f7e832a2de1032e78dc059208f9ec354170b2b1cab992b52ac01e"
                       "6c0e4e1b0112686962edc53ab226dafcc9fc7baed2cd9307160e857"
                       "2edb125935db49289b178f35a8ad23f4f801";
    ecdsa_param.d =
        "52ad53e849e30bec0e6345c3e9d98ebc808b19496c1ef16d72ab4a00bbb8c634";
    ecdsa_param.k =
        "8650c30712fc253610884fbba4a332a4574d4b7822f7776cab1df8f5fa05442a";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "d3e9e82051d4c84d699453c9ff44c7c09f6523bb92232bcf30bf3c3"
                       "80224249de2964e871d56a364d6955c81ef91d06482a6c7c61bc70f"
                       "66ef22fad128d15416e7174312619134f968f1009f92cbf99248932"
                       "efb533ff113fb6d949e21d6b80dfbbe69010c8d1ccb0f3808ea309b"
                       "b0bac1a222168c95b088847e613749b19d04";
    ecdsa_param.d =
        "80754962a864be1803bc441fa331e126005bfc6d8b09ed38b7e69d9a030a5d27";
    ecdsa_param.k =
        "738e050aeefe54ecba5be5f93a97bbcb7557d701f9da2d7e88483454b97b55a8";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "968951c2c1918436fe19fa2fe2152656a08f9a6b8aa6201920f1b42"
                       "4da98cee71928897ff087620cc5c551320b1e75a1e98d7d98a5bd53"
                       "61c9393759614a6087cc0f7fb01fcb173783eb4c4c23961a8231ac4"
                       "a07d72e683b0c1bd4c51ef1b031df875e7b8d5a6e0628949f5b8f15"
                       "7f43dccaea3b2a4fc11181e6b451e06ceb37";
    ecdsa_param.d =
        "cfa8c8bd810eb0d73585f36280ecdd296ee098511be8ad5eac68984eca8eb19d";
    ecdsa_param.k =
        "2d6b449bb38b543d6b6d34ff8cb053f5e5b337f949b069b21f421995ebb28823";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "78048628932e1c1cdd1e70932bd7b76f704ba08d7e7d825d3de763b"
                       "f1a062315f4af16eccefe0b6ebadccaf403d013f50833ce2c54e24e"
                       "ea8345e25f93b69bb048988d102240225ceacf5003e2abdcc90299f"
                       "4bf2c101585d36ecdd7a155953c674789d070480d1ef47cc7858e97"
                       "a6d87c41c6922a00ea12539f251826e141b4";
    ecdsa_param.d =
        "b2021e2665ce543b7feadd0cd5a4bd57ffcc5b32deb860b4d736d9880855da3c";
    ecdsa_param.k =
        "b15bbce4b382145de7ecd670d947e77555ef7cd1693bd53c694e2b52b04d10e1";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "9b0800c443e693067591737fdbcf0966fdfa50872d41d0c189d87cb"
                       "c34c2771ee5e1255fd604f09fcf167fda16437c245d299147299c69"
                       "046895d22482db29aba37ff57f756716cd3d6223077f747c4caffbe"
                       "cc0a7c9dfaaafd9a9817470ded8777e6355838ac54d11b2f0fc3f43"
                       "668ff949cc31de0c2d15af5ef17884e4d66a";
    ecdsa_param.d =
        "0c9bce6a568ca239395fc3552755575cbcdddb1d89f6f5ab354517a057b17b48";
    ecdsa_param.k =
        "d414f1525cdcc41eba1652de017c034ebcc7946cb2efe4713d09f67c85b83153";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "fc3b8291c172dae635a6859f525beaf01cf683765d7c86f1a4d768d"
                       "f7cae055f639eccc08d7a0272394d949f82d5e12d69c08e2483e11a"
                       "1d28a4c61f18193106e12e5de4a9d0b4bf341e2acd6b715dc83ae5f"
                       "f63328f8346f35521ca378b311299947f63ec593a5e32e6bd11ec4e"
                       "db0e75302a9f54d21226d23314729e061016";
    ecdsa_param.d =
        "1daa385ec7c7f8a09adfcaea42801a4de4c889fb5c6eb4e92bc611d596d68e3f";
    ecdsa_param.k =
        "7707db348ee6f60365b43a2a994e9b40ed56fe03c2c31c7e781bc4ffadcba760";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp256r1 && dgst_len == SHA256_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd254"
                       "82935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f"
                       "9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28"
                       "175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799"
                       "790fe2d308d16146d5c9b0d0debd97d79ce8";
    ecdsa_param.d =
        "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";
    ecdsa_param.k =
        "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366"
                       "e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d"
                       "7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4"
                       "e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b01"
                       "1ce375b56621a20642b4d36e060db4524af1";
    ecdsa_param.d =
        "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813";
    ecdsa_param.k =
        "6d3e71882c3b83b156bb14e0ab184aa9fb728068d3ae9fac421187ae0b2f34c6";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "3c054e333a94259c36af09ab5b4ff9beb3492f8d5b4282d16801dac"
                       "cb29f70fe61a0b37ffef5c04cd1b70e85b1f549a1c4dc672985e50f"
                       "43ea037efa9964f096b5f62f7ffdf8d6bfb2cc859558f5a393cb949"
                       "dbd48f269343b5263dcdb9c556eca074f2e98e6d94c2c29a677afaf"
                       "806edf79b15a3fcd46e7067b7669f83188ee";
    ecdsa_param.d =
        "e283871239837e13b95f789e6e1af63bf61c918c992e62bca040d64cad1fc2ef";
    ecdsa_param.k =
        "ad5e887eb2b380b8d8280ad6e5ff8a60f4d26243e0124c2f31a297b5d0835de2";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "0989122410d522af64ceb07da2c865219046b4c3d9d99b01278c07f"
                       "f63eaf1039cb787ae9e2dd46436cc0415f280c562bebb83a23e639e"
                       "476a02ec8cff7ea06cd12c86dcc3adefbf1a9e9a9b6646c7599ec63"
                       "1b0da9a60debeb9b3e19324977f3b4f36892c8a38671c8e1cc8e50f"
                       "cd50f9e51deaf98272f9266fc702e4e57c30";
    ecdsa_param.d =
        "a3d2d3b7596f6592ce98b4bfe10d41837f10027a90d7bb75349490018cf72d07";
    ecdsa_param.k =
        "24fc90e1da13f17ef9fe84cc96b9471ed1aaac17e3a4bae33a115df4e5834f18";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "dc66e39f9bbfd9865318531ffe9207f934fa615a5b285708a5e9c46"
                       "b7775150e818d7f24d2a123df3672fff2094e3fd3df6fbe259e3989"
                       "dd5edfcccbe7d45e26a775a5c4329a084f057c42c13f3248e3fd6f0"
                       "c76678f890f513c32292dd306eaa84a59abe34b16cb5e38d0e88552"
                       "5d10336ca443e1682aa04a7af832b0eee4e7";
    ecdsa_param.d =
        "53a0e8a8fe93db01e7ae94e1a9882a102ebd079b3a535827d583626c272d280d";
    ecdsa_param.k =
        "5d833e8d24cc7a402d7ee7ec852a3587cddeb48358cea71b0bedb8fabe84e0c4";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "600974e7d8c5508e2c1aab0783ad0d7c4494ab2b4da265c2fe49642"
                       "1c4df238b0be25f25659157c8a225fb03953607f7df996acfd402f1"
                       "47e37aee2f1693e3bf1c35eab3ae360a2bd91d04622ea47f83d863d"
                       "2dfecb618e8b8bdc39e17d15d672eee03bb4ce2cc5cf6b217e5faf3"
                       "f336fdd87d972d3a8b8a593ba85955cc9d71";
    ecdsa_param.d =
        "4af107e8e2194c830ffb712a65511bc9186a133007855b49ab4b3833aefc4a1d";
    ecdsa_param.k =
        "e18f96f84dfa2fd3cdfaec9159d4c338cd54ad314134f0b31e20591fc238d0ab";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "dfa6cb9b39adda6c74cc8b2a8b53a12c499ab9dee01b4123642b4f1"
                       "1af336a91a5c9ce0520eb2395a6190ecbf6169c4cba81941de8e76c"
                       "9c908eb843b98ce95e0da29c5d4388040264e05e07030a577cc5d17"
                       "6387154eabae2af52a83e85c61c7c61da930c9b19e45d7e34c8516d"
                       "c3c238fddd6e450a77455d534c48a152010b";
    ecdsa_param.d =
        "78dfaa09f1076850b3e206e477494cddcfb822aaa0128475053592c48ebaf4ab";
    ecdsa_param.k =
        "295544dbb2da3da170741c9b2c6551d40af7ed4e891445f11a02b66a5c258a77";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "51d2547cbff92431174aa7fc7302139519d98071c755ff1c92e4694"
                       "b58587ea560f72f32fc6dd4dee7d22bb7387381d0256e2862d0644c"
                       "df2c277c5d740fa089830eb52bf79d1e75b8596ecf0ea58a0b9df61"
                       "e0c9754bfcd62efab6ea1bd216bf181c5593da79f10135a9bc6e164"
                       "f1854bc8859734341aad237ba29a81a3fc8b";
    ecdsa_param.d =
        "80e692e3eb9fcd8c7d44e7de9f7a5952686407f90025a1d87e52c7096a62618a";
    ecdsa_param.k =
        "7c80fd66d62cc076cef2d030c17c0a69c99611549cb32c4ff662475adbe84b22";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "558c2ac13026402bad4a0a83ebc9468e50f7ffab06d6f981e5db1d0"
                       "82098065bcff6f21a7a74558b1e8612914b8b5a0aa28ed5b574c36a"
                       "c4ea5868432a62bb8ef0695d27c1e3ceaf75c7b251c65ddb268696f"
                       "07c16d2767973d85beb443f211e6445e7fe5d46f0dce70d58a4cd9f"
                       "e70688c035688ea8c6baec65a5fc7e2c93e8";
    ecdsa_param.d =
        "5e666c0db0214c3b627a8e48541cc84a8b6fd15f300da4dff5d18aec6c55b881";
    ecdsa_param.k =
        "2e7625a48874d86c9e467f890aaa7cd6ebdf71c0102bfdcfa24565d6af3fdce9";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90"
                       "a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7"
                       "920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc2"
                       "4024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e6"
                       "8151fc4aee5adebb066eb6da4eaa5681378e";
    ecdsa_param.d =
        "f73f455271c877c4d5334627e37c278f68d143014b0a05aa62f308b2101c5308";
    ecdsa_param.k =
        "62f8665fd6e26b3fa069e85281777a9b1f0dfd2c0b9f54a086d0c109ff9fd615";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "f8248ad47d97c18c984f1f5c10950dc1404713c56b6ea397e01e6dd"
                       "925e903b4fadfe2c9e877169e71ce3c7fe5ce70ee4255d9cdc26f69"
                       "43bf48687874de64f6cf30a012512e787b88059bbf561162bdcc23a"
                       "3742c835ac144cc14167b1bd6727e940540a9c99f3cbb41fb1dcb00"
                       "d76dda04995847c657f4c19d303eb09eb48a";
    ecdsa_param.d =
        "b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906";
    ecdsa_param.k =
        "72b656f6b35b9ccbc712c9f1f3b1a14cbbebaec41c4bca8da18f492a062d6f6f";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "3b6ee2425940b3d240d35b97b6dcd61ed3423d8e71a0ada35d47b32"
                       "2d17b35ea0472f35edd1d252f87b8b65ef4b716669fc9ac28b00d34"
                       "a9d66ad118c9d94e7f46d0b4f6c2b2d339fd6bcd351241a387cc826"
                       "09057048c12c4ec3d85c661975c45b300cb96930d89370a327c98b6"
                       "7defaa89497aa8ef994c77f1130f752f94a4";
    ecdsa_param.d =
        "d4234bebfbc821050341a37e1240efe5e33763cbbb2ef76a1c79e24724e5a5e7";
    ecdsa_param.k =
        "d926fe10f1bfd9855610f4f5a3d666b1a149344057e35537373372ead8b1a778";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "c5204b81ec0a4df5b7e9fda3dc245f98082ae7f4efe81998dcaa286"
                       "bd4507ca840a53d21b01e904f55e38f78c3757d5a5a4a44b1d5d4e4"
                       "80be3afb5b394a5d2840af42b1b4083d40afbfe22d702f370d32dbf"
                       "d392e128ea4724d66a3701da41ae2f03bb4d91bb946c7969404cb54"
                       "4f71eb7a49eb4c4ec55799bda1eb545143a7";
    ecdsa_param.d =
        "b58f5211dff440626bb56d0ad483193d606cf21f36d9830543327292f4d25d8c";
    ecdsa_param.k =
        "e158bf4a2d19a99149d9cdb879294ccb7aaeae03d75ddd616ef8ae51a6dc1071";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "72e81fe221fb402148d8b7ab03549f1180bcc03d41ca59d7653801f"
                       "0ba853add1f6d29edd7f9abc621b2d548f8dbf8979bd16608d2d8fc"
                       "3260b4ebc0dd42482481d548c7075711b5759649c41f439fad69954"
                       "956c9326841ea6492956829f9e0dc789f73633b40f6ac77bcae6dfc"
                       "7930cfe89e526d1684365c5b0be2437fdb01";
    ecdsa_param.d =
        "54c066711cdb061eda07e5275f7e95a9962c6764b84f6f1f3ab5a588e0a2afb1";
    ecdsa_param.k =
        "646fe933e96c3b8f9f507498e907fdd201f08478d0202c752a7c2cfebf4d061a";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "21188c3edd5de088dacc1076b9e1bcecd79de1003c2414c38661730"
                       "54dc82dde85169baa77993adb20c269f60a5226111828578bcc7c29"
                       "e6e8d2dae81806152c8ba0c6ada1986a1983ebeec1473a73a04795b"
                       "6319d48662d40881c1723a706f516fe75300f92408aa1dc6ae4288d"
                       "2046f23c1aa2e54b7fb6448a0da922bd7f34";
    ecdsa_param.d =
        "34fa4682bf6cb5b16783adcd18f0e6879b92185f76d7c920409f904f522db4b1";
    ecdsa_param.k =
        "a6f463ee72c9492bc792fe98163112837aebd07bab7a84aaed05be64db3086f4";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp256r1 && dgst_len == SHA384_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "e0b8596b375f3306bbc6e77a0b42f7469d7e83635990e74aa6d7135"
                       "94a3a24498feff5006790742d9c2e9b47d714bee932435db747c6e7"
                       "33e3d8de41f2f91311f2e9fd8e025651631ffd84f66732d3473fbd1"
                       "627e63dc7194048ebec93c95c159b5039ab5e79e42c80b484a943f1"
                       "25de3da1e04e5bf9c16671ad55a1117d3306";
    ecdsa_param.d =
        "b6faf2c8922235c589c27368a3b3e6e2f42eb6073bf9507f19eed0746c79dced";
    ecdsa_param.k =
        "9980b9cdfcef3ab8e219b9827ed6afdd4dbf20bd927e9cd01f15762703487007";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "099a0131179fff4c6928e49886d2fdb3a9f239b7dd5fa828a52cbbe"
                       "3fcfabecfbba3e192159b887b5d13aa1e14e6a07ccbb21f6ad8b7e8"
                       "8fee6bea9b86dea40ffb962f38554056fb7c5bb486418915f7e7e9b"
                       "9033fe3baaf9a069db98bc02fa8af3d3d1859a11375d6f98aa2ce63"
                       "2606d0800dff7f55b40f971a8586ed6b39e9";
    ecdsa_param.d =
        "118958fd0ff0f0b0ed11d3cf8fa664bc17cdb5fed1f4a8fc52d0b1ae30412181";
    ecdsa_param.k =
        "23129a99eeda3d99a44a5778a46e8e7568b91c31fb7a8628c5d9820d4bed4a6b";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "0fbc07ea947c946bea26afa10c51511039b94ddbc4e2e4184ca3559"
                       "260da24a14522d1497ca5e77a5d1a8e86583aeea1f5d4ff9b04a6aa"
                       "0de79cd88fdb85e01f171143535f2f7c23b050289d7e05cebccdd13"
                       "1888572534bae0061bdcc3015206b9270b0d5af9f1da2f9de91772d"
                       "178a632c3261a1e7b3fb255608b3801962f9";
    ecdsa_param.d =
        "3e647357cd5b754fad0fdb876eaf9b1abd7b60536f383c81ce5745ec80826431";
    ecdsa_param.k =
        "9beab7722f0bcb468e5f234e074170a60225255de494108459abdf603c6e8b35";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "1e38d750d936d8522e9db1873fb4996bef97f8da3c6674a1223d292"
                       "63f1234a90b751785316444e9ba698bc8ab6cd010638d182c9adad4"
                       "e334b2bd7529f0ae8e9a52ad60f59804b2d780ed52bdd33b0bf5400"
                       "147c28b4304e5e3434505ae7ce30d4b239e7e6f0ecf058badd5b388"
                       "eddbad64d24d2430dd04b4ddee98f972988f";
    ecdsa_param.d =
        "76c17c2efc99891f3697ba4d71850e5816a1b65562cc39a13da4b6da9051b0fd";
    ecdsa_param.k =
        "77cffa6f9a73904306f9fcd3f6bbb37f52d71e39931bb4aec28f9b076e436ccf";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "abcf0e0f046b2e0672d1cc6c0a114905627cbbdefdf9752f0c31660"
                       "aa95f2d0ede72d17919a9e9b1add3213164e0c9b5ae3c76f1a2f79d"
                       "3eeb444e6741521019d8bd5ca391b28c1063347f07afcfbb705be4b"
                       "52261c19ebaf1d6f054a74d86fb5d091fa7f229450996b76f0ada5f"
                       "977b09b58488eebfb5f5e9539a8fd89662ab";
    ecdsa_param.d =
        "67b9dea6a575b5103999efffce29cca688c781782a41129fdecbce76608174de";
    ecdsa_param.k =
        "d02617f26ede3584f0afcfc89554cdfb2ae188c192092fdde3436335fafe43f1";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "dc3d4884c741a4a687593c79fb4e35c5c13c781dca16db561d7e393"
                       "577f7b62ca41a6e259fc1fb8d0c4e1e062517a0fdf95558b7799f20"
                       "c211796167953e6372c11829beec64869d67bf3ee1f1455dd87acfb"
                       "dbcc597056e7fb347a17688ad32fda7ccc3572da7677d7255c26173"
                       "8f07763cd45973c728c6e9adbeecadc3d961";
    ecdsa_param.d =
        "ecf644ea9b6c3a04fdfe2de4fdcb55fdcdfcf738c0b3176575fa91515194b566";
    ecdsa_param.k =
        "53291d51f68d9a12d1dcdc58892b2f786cc15f631f16997d2a49bace513557d4";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "719bf1911ae5b5e08f1d97b92a5089c0ab9d6f1c175ac7199086aee"
                       "aa416a17e6d6f8486c711d386f284f096296689a54d330c8efb0f5f"
                       "a1c5ba128d3234a3da856c2a94667ef7103616a64c913135f4e1dc5"
                       "0e38daa60610f732ad1bedfcc396f87169392520314a6b6b9af6793"
                       "dbabad4599525228cc7c9c32c4d8e097ddf6";
    ecdsa_param.d =
        "4961485cbc978f8456ec5ac7cfc9f7d9298f99415ecae69c8491b258c029bfee";
    ecdsa_param.k =
        "373a825b5a74b7b9e02f8d4d876b577b4c3984168d704ba9f95b19c05ed590af";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "7cf19f4c851e97c5bca11a39f0074c3b7bd3274e7dd75d0447b7b84"
                       "995dfc9f716bf08c25347f56fcc5e5149cb3f9cfb39d408ace5a5c4"
                       "7e75f7a827fa0bb9921bb5b23a6053dbe1fa2bba341ac874d9b1333"
                       "fc4dc224854949f5c8d8a5fedd02fb26fdfcd3be351aec0fcbef189"
                       "72956c6ec0effaf057eb4420b6d28e0c008c";
    ecdsa_param.d =
        "587907e7f215cf0d2cb2c9e6963d45b6e535ed426c828a6ea2fb637cca4c5cbd";
    ecdsa_param.k =
        "6b8eb7c0d8af9456b95dd70561a0e902863e6dfa1c28d0fd4a0509f1c2a647b2";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "b892ffabb809e98a99b0a79895445fc734fa1b6159f9cddb6d21e51"
                       "0708bdab6076633ac30aaef43db566c0d21f4381db46711fe3812c5"
                       "ce0fb4a40e3d5d8ab24e4e82d3560c6dc7c37794ee17d4a144065ef"
                       "99c8d1c88bc22ad8c4c27d85ad518fa5747ae35276fc104829d3f5c"
                       "72fc2a9ea55a1c3a87007cd133263f79e405";
    ecdsa_param.d =
        "24b1e5676d1a9d6b645a984141a157c124531feeb92d915110aef474b1e27666";
    ecdsa_param.k =
        "88794923d8943b5dbcc7a7a76503880ff7da632b0883aaa60a9fcc71bf880fd6";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "8144e37014c95e13231cbd6fa64772771f93b44e37f7b02f592099c"
                       "c146343edd4f4ec9fa1bc68d7f2e9ee78fc370443aa2803ff4ca52e"
                       "e49a2f4daf2c8181ea7b8475b3a0f608fc3279d09e2d057fbe3f2ff"
                       "be5133796124781299c6da60cfe7ecea3abc30706ded2cdf18f9d78"
                       "8e59f2c31662df3abe01a9b12304fb8d5c8c";
    ecdsa_param.d =
        "bce49c7b03dcdc72393b0a67cf5aa5df870f5aaa6137ada1edc7862e0981ec67";
    ecdsa_param.k =
        "89e690d78a5e0d2b8ce9f7fcbf34e2605fd9584760fa7729043397612dd21f94";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "a3683d120807f0a030feed679785326698c3702f1983eaba1b70ddf"
                       "a7f0b3188060b845e2b67ed57ee68087746710450f7427cb34655d7"
                       "19c0acbc09ac696adb4b22aba1b9322b7111076e67053a55f62b501"
                       "a4bca0ad9d50a868f51aeeb4ef27823236f5267e8da83e143047422"
                       "ce140d66e05e44dc84fb3a4506b2a5d7caa8";
    ecdsa_param.d =
        "73188a923bc0b289e81c3db48d826917910f1b957700f8925425c1fb27cabab9";
    ecdsa_param.k =
        "ec90584ab3b383b590626f36ed4f5110e49888aec7ae7a9c5ea62dd2dc378666";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "b1df8051b213fc5f636537e37e212eb20b2423e6467a9c7081336a8"
                       "70e6373fc835899d59e546c0ac668cc81ce4921e88f42e6da2a109a"
                       "03b4f4e819a17c955b8d099ec6b282fb495258dca13ec779c459da9"
                       "09475519a3477223c06b99afbd77f9922e7cbef844b93f3ce5f50db"
                       "816b2e0d8b1575d2e17a6b8db9111d6da578";
    ecdsa_param.d =
        "f637d55763fe819541588e0c603f288a693cc66823c6bb7b8e003bd38580ebce";
    ecdsa_param.k =
        "4d578f5099636234d9c1d566f1215d5d887ae5d47022be17dbf32a11a03f053b";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "0b918ede985b5c491797d0a81446b2933be312f419b212e3aae9ba5"
                       "914c00af431747a9d287a7c7761e9bcbc8a12aaf9d4a76d13dad59f"
                       "c742f8f218ef66eb67035220a07acc1a357c5b562ecb6b895cf725c"
                       "4230412fefac72097f2c2b829ed58742d7c327cad0f1058df1bddd4"
                       "ae9c6d2aba25480424308684cecd6517cdd8";
    ecdsa_param.d =
        "2e357d51517ff93b821f895932fddded8347f32596b812308e6f1baf7dd8a47f";
    ecdsa_param.k =
        "be522b0940b9a40d84bf790fe6abdc252877e671f2efa63a33a65a512fc2aa5c";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "0fab26fde1a4467ca930dbe513ccc3452b70313cccde2994eead2fd"
                       "e85c8da1db84d7d06a024c9e88629d5344224a4eae01b21a2665d5f"
                       "7f36d5524bf5367d7f8b6a71ea05d413d4afde33777f0a3be49c9e6"
                       "aa29ea447746a9e77ce27232a550b31dd4e7c9bc8913485f2dc83a5"
                       "6298051c92461fd46b14cc895c300a4fb874";
    ecdsa_param.d =
        "77d60cacbbac86ab89009403c97289b5900466856887d3e6112af427f7f0f50b";
    ecdsa_param.k =
        "06c1e692b045f425a21347ecf72833d0242906c7c1094f805566cdcb1256e394";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "7843f157ef8566722a7d69da67de7599ee65cb3975508f70c612b32"
                       "89190e364141781e0b832f2d9627122742f4b5871ceeafcd09ba5ec"
                       "90cae6bcc01ae32b50f13f63918dfb5177df9797c6273b92d103c3f"
                       "7a3fc2050d2b196cc872c57b77f9bdb1782d4195445fcc6236dd8bd"
                       "14c8bcbc8223a6739f6a17c9a861e8c821a6";
    ecdsa_param.d =
        "486854e77962117f49e09378de6c9e3b3522fa752b10b2c810bf48db584d7388";
    ecdsa_param.k =
        "e4f77c6442eca239b01b0254e11a4182782d96f48ab521cc3d1d68df12b5a41a";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp256r1 && dgst_len == SHA512_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "6c8572b6a3a4a9e8e03dbeed99334d41661b8a8417074f335ab1845"
                       "f6cc852adb8c01d9820fcf8e10699cc827a8fbdca2cbd46cc66e4e6"
                       "b7ba41ec3efa733587e4a30ec552cd8ddab8163e148e50f4d090782"
                       "897f3ddac84a41e1fcfe8c56b6152c0097b0d634b41011471ffd004"
                       "f43eb4aafc038197ec6bae2b4470e869bded";
    ecdsa_param.d =
        "9dd0d3a3d514c2a8adb162b81e3adfba3299309f7d2018f607bdb15b1a25f499";
    ecdsa_param.k =
        "9106192170ccb3c64684d48287bb81bbed51b40d503462c900e5c7aae43e380a";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "7e3c8fe162d48cc8c5b11b5e5ebc05ebc45c439bdbc0b0902145921"
                       "b8383037cb0812222031598cd1a56fa71694fbd304cc62938233465"
                       "ec39c6e49f57dfe823983b6923c4e865633949183e6b90e9e06d827"
                       "5f3907d97967d47b6239fe2847b7d49cf16ba69d2862083cf1bccf7"
                       "afe34fdc90e21998964107b64abe6b89d126";
    ecdsa_param.d =
        "f9bf909b7973bf0e3dad0e43dcb2d7fa8bda49dbe6e5357f8f0e2bd119be30e6";
    ecdsa_param.k =
        "e547791f7185850f03d0c58419648f65b9d29cdc22ed1de2a64280220cfcafba";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "d5aa8ac9218ca661cd177756af6fbb5a40a3fecfd4eea6d5872fbb9"
                       "a2884784aa9b5f0c023a6e0da5cf6364754ee6465b4ee2d0ddc745b"
                       "02994c98427a213c849537da5a4477b3abfe02648be67f26e80b56a"
                       "33150490d062aaac137aa47f11cfeddba855bab9e4e028532a56332"
                       "6d927f9e6e3292b1fb248ee90b6f429798db";
    ecdsa_param.d =
        "724567d21ef682dfc6dc4d46853880cfa86fe6fea0efd51fac456f03c3d36ead";
    ecdsa_param.k =
        "79d6c967ed23c763ece9ca4b026218004c84dc2d4ccc86cf05c5d0f791f6279b";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "790b06054afc9c3fc4dfe72df19dd5d68d108cfcfca6212804f6d53"
                       "4fd2fbe489bd8f64bf205ce04bcb50124a12ce5238fc3fe7dd76e6f"
                       "a640206af52549f133d593a1bfd423ab737f3326fa79433cde29323"
                       "6f90d4238f0dd38ed69492ddbd9c3eae583b6325a95dec3166fe52b"
                       "21658293d8c137830ef45297d67813b7a508";
    ecdsa_param.d =
        "29c5d54d7d1f099d50f949bfce8d6073dae059c5a19cc70834722f18a7199edd";
    ecdsa_param.k =
        "0508ad7774908b5705895fda5c3b7a3032bf85dab7232bf981177019f3d76460";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "6d549aa87afdb8bfa60d22a68e2783b27e8db46041e4df04be0c261"
                       "c4734b608a96f198d1cdb8d082ae48579ec9defcf21fbc72803764a"
                       "58c31e5323d5452b9fb57c8991d31749140da7ef067b18bf0d7dfba"
                       "e6eefd0d8064f334bf7e9ec1e028daed4e86e17635ec2e409a3ed12"
                       "38048a45882c5c57501b314e636b9bc81cbe";
    ecdsa_param.d =
        "0d8095da1abba06b0d349c226511f642dabbf1043ad41baa4e14297afe8a3117";
    ecdsa_param.k =
        "5165c54def4026ab648f7768c4f1488bcb183f6db7ffe02c7022a529a116482a";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "1906e48b7f889ee3ff7ab0807a7aa88f53f4018808870bfed6372a7"
                       "7330c737647961324c2b4d46f6ee8b01190474951a701b048ae8657"
                       "9ff8e3fc889fecf926b17f98958ac7534e6e781ca2db2baa380dec7"
                       "66cfb2a3eca2a9d5818967d64dfab84f768d24ec122eebacaab0a4d"
                       "c3a75f37331bb1c43dd8966cc09ec4945bbd";
    ecdsa_param.d =
        "52fe57da3427b1a75cb816f61c4e8e0e0551b94c01382b1a80837940ed579e61";
    ecdsa_param.k =
        "0464fe9674b01ff5bd8be21af3399fad66f90ad30f4e8ee6e2eb9bcccfd5185c";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "7b59fef13daf01afec35dea3276541be681c4916767f34d4e874464"
                       "d20979863ee77ad0fd1635bcdf93e9f62ed69ae52ec90aab5bbf87f"
                       "8951213747ccec9f38c775c1df1e9d7f735c2ce39b42edb3b0c5086"
                       "247556cfea539995c5d9689765288ec600848ecf085c01ca738bbef"
                       "11f5d12d4457db988b4add90be00781024ad";
    ecdsa_param.d =
        "003d91611445919f59bfe3ca71fe0bfdeb0e39a7195e83ac03a37c7eceef0df2";
    ecdsa_param.k =
        "ef9df291ea27a4b45708f7608723c27d7d56b7df0599a54bc2c2fabbff373b40";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "041a6767a935dc3d8985eb4e608b0cbfebe7f93789d4200bcfe5952"
                       "77ac2b0f402889b580b72def5da778a680fd380c955421f626d52dd"
                       "9a83ea180187b850e1b72a4ec6dd63235e598fd15a9b19f8ce9aec1"
                       "d23f0bd6ea4d92360d50f951152bc9a01354732ba0cf90aaed33c30"
                       "7c1de8fa3d14f9489151b8377b57c7215f0b";
    ecdsa_param.d =
        "48f13d393899cd835c4193670ec62f28e4c4903e0bbe5817bf0996831a720bb7";
    ecdsa_param.k =
        "efed736e627899fea944007eea39a4a63c0c2e26491cd12adb546be3e5c68f7d";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "7905a9036e022c78b2c9efd40b77b0a194fbc1d45462779b0b76ad3"
                       "0dc52c564e48a493d8249a061e62f26f453ba566538a4d43c64fb9f"
                       "dbd1f36409316433c6f074e1b47b544a847de25fc67d81ac801ed9f"
                       "7371a43da39001c90766f943e629d74d0436ba1240c3d7fab990d58"
                       "6a6d6ef1771786722df56448815f2feda48f";
    ecdsa_param.d =
        "95c99cf9ec26480275f23de419e41bb779590f0eab5cf9095d37dd70cb75e870";
    ecdsa_param.k =
        "4c08dd0f8b72ae9c674e1e448d4e2afe3a1ee69927fa23bbff3716f0b99553b7";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "cf25e4642d4f39d15afb7aec79469d82fc9aedb8f89964e79b749a8"
                       "52d931d37436502804e39555f5a3c75dd958fd5291ada647c1a5e38"
                       "fe7b1048f16f2b711fdd5d39acc0812ca65bd50d7f8119f2fd195ab"
                       "16633503a78ee9102c1f9c4c22568e0b54bd4fa3f5ff7b49160bf23"
                       "e7e2231b1ebebbdaf0e4a7d4484158a87e07";
    ecdsa_param.d =
        "e15e835d0e2217bc7c6f05a498f20af1cd56f2f165c23d225eb3360aa2c5cbcf";
    ecdsa_param.k =
        "c9f621441c235fc47ec34eef4c08625df1ec74918e1f86075b753f2589f4c60b";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "7562c445b35883cc937be6349b4cefc3556a80255d70f09e28c3f39"
                       "3daac19442a7eecedcdfbe8f7628e30cd8939537ec56d5c9645d433"
                       "40eb4e78fc5dd4322de8a07966b262770d7ff13a071ff3dce560718"
                       "e60ed3086b7e0003a6abafe91af90af86733ce8689440bf73d2aa0a"
                       "cfe9776036e877599acbabfcb03bb3b50faa";
    ecdsa_param.d =
        "808c08c0d77423a6feaaffc8f98a2948f17726e67c15eeae4e672edbe388f98c";
    ecdsa_param.k =
        "1f6d4a905c761a53d54c362976717d0d7fc94d222bb5489e4830080a1a67535d";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "051c2db8e71e44653ea1cb0afc9e0abdf12658e9e761bfb767c20c7"
                       "ab4adfcb18ed9b5c372a3ac11d8a43c55f7f99b33355437891686d4"
                       "2362abd71db8b6d84dd694d6982f0612178a937aa934b9ac3c0794c"
                       "39027bdd767841c4370666c80dbc0f8132ca27474f553d266deefd7"
                       "c9dbad6d734f9006bb557567701bb7e6a7c9";
    ecdsa_param.d =
        "f7c6315f0081acd8f09c7a2c3ec1b7ece20180b0a6365a27dcd8f71b729558f9";
    ecdsa_param.k =
        "68c299be2c0c6d52d208d5d1a9e0ffa2af19b4833271404e5876e0aa93987866";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "4dcb7b62ba31b866fce7c1feedf0be1f67bf611dbc2e2e86f004422"
                       "f67b3bc1839c6958eb1dc3ead137c3d7f88aa97244577a775c8021b"
                       "1642a8647bba82871e3c15d0749ed343ea6cad38f123835d8ef66b0"
                       "719273105e924e8685b65fd5dc430efbc35b05a6097f17ebc5943cd"
                       "cd9abcba752b7f8f37027409bd6e11cd158f";
    ecdsa_param.d =
        "f547735a9409386dbff719ce2dae03c50cb437d6b30cc7fa3ea20d9aec17e5a5";
    ecdsa_param.k =
        "91bd7d97f7ed3253cedefc144771bb8acbbda6eb24f9d752bbe1dd018e1384c7";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "efe55737771070d5ac79236b04e3fbaf4f2e9bed187d1930680fcf1"
                       "aba769674bf426310f21245006f528779347d28b8aeacd2b1d5e345"
                       "6dcbf188b2be8c07f19219e4067c1e7c9714784285d8bac79a76b56"
                       "f2e2676ea93994f11eb573af1d03fc8ed1118eafc7f07a82f3263c3"
                       "3eb85e497e18f435d4076a774f42d276c323";
    ecdsa_param.d =
        "26a1aa4b927a516b661986895aff58f40b78cc5d0c767eda7eaa3dbb835b5628";
    ecdsa_param.k =
        "f98e1933c7fad4acbe94d95c1b013e1d6931fa8f67e6dbb677b564ef7c3e56ce";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "ea95859cc13cccb37198d919803be89c2ee10befdcaf5d5afa09dcc"
                       "529d333ae1e4ffd3bd8ba8642203badd7a80a3f77eeee9402eed365"
                       "d53f05c1a995c536f8236ba6b6ff8897393506660cc8ea82b2163aa"
                       "6a1855251c87d935e23857fe35b889427b449de7274d7754bdeace9"
                       "60b4303c5dd5f745a5cfd580293d6548c832";
    ecdsa_param.d =
        "6a5ca39aae2d45aa331f18a8598a3f2db32781f7c92efd4f64ee3bbe0c4c4e49";
    ecdsa_param.k =
        "dac00c462bc85bf39c31b5e01df33e2ec1569e6efcb334bf18f0951992ac6160";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp384r1 && dgst_len == SHA224_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "39f0b25d4c15b09a0692b22fbacbb5f8aee184cb75887e2ebe0cd3b"
                       "e5d3815d29f9b587e10b3168c939054a89df11068e5c3fac21af742"
                       "bf4c3e9512f5569674e7ad8b39042bcd73e4b7ce3e64fbea1c434ed"
                       "01ad4ad8b5b569f6a0b9a1144f94097925672e59ba97bc4d33be2fa"
                       "21b46c3dadbfb3a1f89afa199d4b44189938";
    ecdsa_param.d = "0af857beff08046f23b03c4299eda86490393bde88e4f74348886b2005"
                    "55276b93b37d4f6fdec17c0ea581a30c59c727";
    ecdsa_param.k = "e2f0ce83c5bbef3a6eccd1744f893bb52952475d2531a2854a88ff0aa9"
                    "b12c65961e2e517fb334ef40e0c0d7a31ed5f5";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "5a3c80e608ed3ac75a6e45f6e94d374271a6d42b67a481860d5d309"
                       "cc8b37c79cb61f1716dc8aa84cb309ef9d68eb7fc6cf4b42333f316"
                       "a5c30e74198c8b340926e340c5de47674a707293c4aa2a1a2274a60"
                       "2f01c26b156e895499c60b38ef53fc2032e7485c168d73700d6fa14"
                       "232596a0e4997854a0b05d02e351b9d3de96";
    ecdsa_param.d = "047dd5baab23f439ec23b58b7e6ff4cc37813cccb4ea73bb2308e6b82b"
                    "3170edfe0e131eca50841bf1b686e651c57246";
    ecdsa_param.k = "f3922351d14f1e5af84faab12fe57ded30f185afe5547aeb3061104740"
                    "ecc42a8df0c27f3877b4d855642b78938c4e05";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "e7d974c5dbd3bfb8a2fb92fdd782f997d04be79e9713944ce13c5eb"
                       "6f75dfdec811b7ee4b3859114b07f263846ae13f795eec8f3cb5b75"
                       "65baff68e0fdd5e09ba8b176d5a71cb03fbc5546e6937fba560acb4"
                       "db24bd42de1851432b96e8ca4078313cb849bce29c9d805258601d6"
                       "7cd0259e255f3048682e8fdbdda3398c3e31";
    ecdsa_param.d = "54ba9c740535574cebc41ca5dc950629674ee94730353ac521aafd1c34"
                    "2d3f8ac52046ed804264e1440d7fe409c45c83";
    ecdsa_param.k = "04324bd078807f6b18507a93ee60da02031717217ee5ce569750737be9"
                    "12be72da087ac00f50e13fdf7249a6ae33f73e";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "a670fda4d1d56c70de1d8680328043b2b7029633caf0ee59ffe1421"
                       "c914bb937133d5a0f9214846b2e0b350455a74c4ab434c56de65a17"
                       "139bb8212bf1c76071a37536fa29348f871dbb26baa92eb93d97e92"
                       "3a6d2ffd9be25cbc33075e494e6db657bd8dc053fe4e17148d8cf6e"
                       "2058164f2b5766750eb01bbe7b361cdb848c";
    ecdsa_param.d = "dabe87bbe95499bac23bc83c8b7307fe04be198f00059e2bf67c9611fe"
                    "affb2c8f274f6aa50eb99c3074186d8067d659";
    ecdsa_param.k = "65a0305854033cbc6fe3ca139c40ca354d45801ecb59f4a923c251dc6b"
                    "25d12d452d99b5d6711fdb5efac812aa464cc4";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "7843f918fe2588bcfe756e1f05b491d913523255aa006818be20b67"
                       "6c957f4edb8df863c6f5f8c15b3b80c7a2aa277b70d53f210bdfb85"
                       "6337980c406ea140e439dd321471407f374f69877b2d82367eed51e"
                       "3c82c13948616dcb301d0c31f8f0352f2846abd9e72071f446a2f1b"
                       "d3339a09ae41b84e150fd18f4ba5d3c6bfa0";
    ecdsa_param.d = "df43107a1deb24d02e31d479087bd669e2bc3e50f1f44b7db9484a7143"
                    "cdca6a3391bddfea72dc940dbce8ec5efbd718";
    ecdsa_param.k = "798abad5a30d1805794540057388ee05e2422901c6335f985b9d4447b3"
                    "ef75524751abfeab6409ad6bf77d4ae3014558";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "caa83d5ab07febbd2e0fe2d63738b9b7b8752594bea7aaf50345b3d"
                       "2f316653a8c9222f2b7877b64679e9573e81461a426029e45b8873a"
                       "575094a1d572e0d32a9f0a9c6bcb9a2868543b7d8bbe4a69a09e732"
                       "1f05f8366cced1b72df526f895b60aed2c39c249653c7839538770d"
                       "4e5f47d3926ec0d168ab6a1af15bf1dca1f7";
    ecdsa_param.d = "ea7a563ba2a7f5ab69973dca1f1a0d1572f0c59817cd3b62ad356c2099"
                    "e2cdca1c553323563f9dfbb333b126d84abc7f";
    ecdsa_param.k = "7b9606b3df7b2a340dbc68d9754de0734e1faeb5a0135578a97628d948"
                    "702235c60b20c8002c8fcf906783e1b389e754";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "594603458d6534974aeeafba919c4d0f4cb6843a3af41204bbb88ae"
                       "b2fca2772d305163dba863da050aabedbaf89db521955d1715de95b"
                       "bcef979ecdc0c976181ece00355385f8a8f8cce127c9eac15ce3e95"
                       "8a3ed686184674ec9a50eb63271606ee7fdcb1323da3c3db8e89cad"
                       "1fb42139a32d08abcfbf0d4ccfca18c89a86";
    ecdsa_param.d = "4cc70cb35b3ddeb0df53a6bd7bd05f8ff4392a2db7344f2d443761484b"
                    "3a468a4ee3d1a8b27113d57283fd18b05f7829";
    ecdsa_param.k = "8eda401d98f5688c34d8dbebcd3991c87c0442b0379154eaa2e5287dab"
                    "e9a9e34cfc1305d11ff68781df25d5611b331d";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "733252d2bd35547838be22656cc7aa67eff0af0b13b428f77267a51"
                       "3c6824c3dbae533068b6817e82665f009560affcfe4b2ddb5b667a6"
                       "44fc1a42d24f24e0947e0dc50fb62c919bc1fe4e7ded5e28f2e6d80"
                       "fcf66a081fb2763526f8def5a81a4ddd38be0b59ee839da1643eeea"
                       "ee7b1927cec12cf3da67c02bc5465151e346";
    ecdsa_param.d = "366d15e4cd7605c71560a418bd0f382fd7cd7ad3090ff1b2dfbed74336"
                    "166a905e1b760cf0bccee7a0e66c5ebfb831f1";
    ecdsa_param.k = "dbe545f920bc3d704c43d834bab21e40df12ec9e16a619a3e6b3f08760"
                    "c26aae6e4fd91fad00f745194794b74bb1baee";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "5a182bd174feb038dfae3346267156bf663167f713dea1ce936b0ed"
                       "b815cd9b8c8e4d411c786ba2494a81442617255db7158b142e720d8"
                       "6c9b56680fb9efd4298cdd69079a28153494c42a24251c7ad42ecf7"
                       "e97eabc1b3997529b2a297cbad2474269b87a0b1e385f2d7f8b6eb8"
                       "d1cd75eaf7e91d1acbecd45d7b2bfbbe3216";
    ecdsa_param.d = "e357d869857a52a06e1ece5593d16407022354780eb9a7cb8575cef327"
                    "f877d22322c006b3c8c11e3d7d296a708bdb6d";
    ecdsa_param.k = "1e77367ac4e10924854d135ad2f2507f39e2bafdbce33ff256bcbe9a73"
                    "29b8d27185218bcc3550aafbe3390e84c77292";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "aaa99fb1c71340d785a18f6f668e898c25cf7a0ac31d13c5b388b72"
                       "33408493a5a109af6d07065376b96f4903df7aba2b2af671a18772b"
                       "b0472490d1240cde28967680727dd4acd47e0308920a75da857a6ee"
                       "edee5b6586d45dff3d8a680599665aa895c89dd7770b824b7dee477"
                       "ac5e7602d409d3cc553090c970b50811dbab";
    ecdsa_param.d = "745a18db47324a3710b993d115b2834339315e84e7006eafd889fb49bd"
                    "3cc5a8b50c90526e65e6c53bddd2916d14bead";
    ecdsa_param.k = "11b9b36720abcac084efdb44c9f5b7d039e3250cb1e9c47850189ba3cf"
                    "c1489d858b2a44df357772b61d919c7e729c0f";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "1fadfa8254d3a0b82d137cfdd82043d5dc1fef195d5297b09cc5cfb"
                       "061f59c933451c0dc2a11b4037f34f88dacb803251f8880c4b72585"
                       "c3c196e6fb23484ca43a191f8e41b9b9a37e2e6fcaab6738c3c62d1"
                       "c98e1c620bb788b7b51a04f998a510efdba0d3418622fe8ce203b3f"
                       "cd553b9b4206365a39031797ad11e49745ec";
    ecdsa_param.d = "93f20963ea5011ff4f26481e359309e634195f6289134087bd2e83eee0"
                    "08c962780a679784ee7ac6acda03d663ed27e0";
    ecdsa_param.k = "3ad308faf04c42ee5ac69d36bc0aa9a96aacf55ea0f27dac4f52e088f0"
                    "23d206340a6324874ffad169ff80624de24c96";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "9ecb6f5ed3ba666a8536a81ef65012c2cb8b433508798d84708abb0"
                       "6dfb75503886f78384fb8c7a4d2d49ef539d9b8a0b60938c7f07471"
                       "dda91f258b0d99691b38a8403a2bb3f956bdfd09baba16d9b687709"
                       "7a9b6213481b47a06e139d23ec7abad5668d21f912fdb70d31bb9ad"
                       "f9b3ce80e308252fa81a51674f88d02db72b";
    ecdsa_param.d = "f175e6ac42fd48ec9d652c10707c039c67c4cc61d8c45a373dcda6e4ca"
                    "6c53e947e49c24e01b48e7cdf92edfe6d316a1";
    ecdsa_param.k = "812dcaa6d4f9a43ccc553288065d13761581485aa903a500a690ccafbd"
                    "330ba4818c977b98c4bb57f8a182a1afacfae9";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "e55bfca78d98e68d1b63688db12485578f36c489766f4d0bfaa0088"
                       "433ff12133aaca455805095f2e655940860958b3ead111d9070778e"
                       "e3bbf3e47e43d9eba8b8d9b1fdf72f793fcde2bcaa334f3e35fa2cc"
                       "a531ea7cf27fe9ccba741e38ac26129b2d612bf54a34e0ae6c166c0"
                       "fef07fcd2b9ac253d7e041a500f7be7b8369";
    ecdsa_param.d = "46c4f0b228b28aaa0ec8cfdf1d0ed3408b7ae049312fb9eaf5f3892720"
                    "e68684cc8ad29844a3dc9d110edf6916dfb8bb";
    ecdsa_param.k = "2a9dd520207c40a379cd4036adef9ee60fa8bc8c0d39b3ad91850ac93f"
                    "d543f218b1688581f23481a090b0e4c73792ac";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "02c6b3c83bd34b288d96409162aa4ff114e9d134bf948046eb5ebcc"
                       "0c7fe9dfceadda83ed69da2fac00c8840f6c702a3fc5e6959d70f7e"
                       "8af923e99e4937232ae3b841ffefd2e62fab3671a7c94a0281b8ea5"
                       "bc176add57c5c9b6893fe7f5d48ce7256b96510810c4e046168a3c5"
                       "be9843b84d5268a50349b3444341aa5490dd";
    ecdsa_param.d = "1d7b71ef01d0d33a8513a3aed3cabb83829589c8021087a740ca65b570"
                    "777089be721a61172b874a22a1f81aef3f8bb6";
    ecdsa_param.k = "d1b25ad25581cad17e96f1d302251681fee5b2efbb71c3c15ff035b214"
                    "5d015d18e0e52dc3187ab5a560277b3a3929b0";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "94f8bfbb9dd6c9b6193e84c2023a27dea00fd48356909faec216197"
                       "2439686c146184f80686bc09e1a698af7df9dea3d24d9e9fd6d7348"
                       "a146339c839282cf8984345dc6a51096d74ad238c35233012ad729f"
                       "262481ec7cd6488f13a6ebac3f3d23438c7ccb5a66e2bf820e92b71"
                       "c730bb12fd64ea1770d1f892e5b1e14a9e5c";
    ecdsa_param.d = "cf53bdd4c91fe5aa4d82f116bd68153c907963fa3c9d478c9462bb03c7"
                    "9039493a8eaeb855773f2df37e4e551d509dcd";
    ecdsa_param.k = "df31908c9289d1fe25e055df199591b23e266433ab8657cc82cb3bca96"
                    "b88720e229f8dfd42d8b78af7db69342430bca";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp384r1 && dgst_len == SHA256_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "663b12ebf44b7ed3872b385477381f4b11adeb0aec9e0e247877631"
                       "3d536376dc8fd5f3c715bb6ddf32c01ee1d6f8b731785732c0d8441"
                       "df636d8145577e7b3138e43c32a61bc1242e0e73d62d624cdc92485"
                       "6076bdbbf1ec04ad4420732ef0c53d42479a08235fcfc4db4d869c4"
                       "eb2828c73928cdc3e3758362d1b770809997";
    ecdsa_param.d = "c602bc74a34592c311a6569661e0832c84f7207274676cc42a89f05816"
                    "2630184b52f0d99b855a7783c987476d7f9e6b";
    ecdsa_param.k = "c10b5c25c4683d0b7827d0d88697cdc0932496b5299b798c0dd1e7af6c"
                    "c757ccb30fcd3d36ead4a804877e24f3a32443";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "784d7f4686c01bea32cb6cab8c089fb25c341080d9832e04feac6ea"
                       "63a341079cbd562a75365c63cf7e63e7e1dddc9e99db75ccee59c52"
                       "95340c2bba36f457690a8f05c62ab001e3d6b333780117d1456a9c8"
                       "b27d6c2504db9c1428dad8ba797a4419914fcc636f0f14ede3fba49"
                       "b023b12a77a2176b0b8ff55a895dcaf8dbce";
    ecdsa_param.d = "0287f62a5aa8432ff5e95618ec8f9ccaa870dde99c30b51b7673378efe"
                    "4ccac598f4bbebbfd8993f9abb747b6ad638b9";
    ecdsa_param.k = "935eeab3edeb281fbd4eead0d9c0babd4b10ff18a31663ee9de3bfa9ae"
                    "8f9d266441158ea31c889ded9b3c592da77fd7";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "45e47fccc5bd6801f237cdbeac8f66ebc75f8b71a6da556d2e00235"
                       "2bd85bf269b6bc7c928d7bb1b0422601e4dd80b29d5906f8fcac212"
                       "fe0eaaf52eda552303259cbcbe532e60abd3d38d786a45e39a2875b"
                       "ce675800a3eaeb9e42983d9fd9031180abd9adccc9ba30c6c198b42"
                       "02c4dd70f241e969a3c412724b9b595bc28a";
    ecdsa_param.d = "d44d3108873977036c9b97e03f914cba2f5775b68c425d550995574081"
                    "191da764acc50196f6d2508082a150af5cd41f";
    ecdsa_param.k = "c80f63e080650c8a21e4f63a62ec909adfb7d877f365d11ee1cb260baf"
                    "112eb4730c161c1d99dba98fc0d5bbd00dc97d";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "c33ff63b4e6891e00b2349b3f2907c417ca355560544a91e24a7a0e"
                       "e260d6850aeded29fc0176b6039ca6187e8333391047cceaf14b107"
                       "7df8f147dad84d36b2dac5666dc2f69dc9b58b88cc73956efdb3b47"
                       "f91831d5875051c76b0c4e9fc087012a1f03eeee85d6745b46aa50b"
                       "d9cb0110c2c94508765cec162ee1aa841d73";
    ecdsa_param.d = "d5b72cbb6ec68aca46b9c27ad992afd8ffa02cb3067b234fcfa6e272e3"
                    "b31be760695ff7df988b57663057ab19dd65e3";
    ecdsa_param.k = "9da6de7c87c101b68db64fea40d97f8ad974ceb88224c6796c690cbf61"
                    "b8bd8eede8470b3caf6e6106b66cf3f0eebd55";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "f562f2b9d84b0e96a52532c3b43c39c8018c738bd8dc3797a7de735"
                       "3971b2729d522d6961b1f2e4df3f6a4bd3653e6d72b74fc0dba92ab"
                       "939c4b542e994e5db6dd8ed4f56f651e699052e791237ae1f552f99"
                       "0ad156226ae8f7bf17fcbfa564f749604f97e9df0879d50985747d9"
                       "81422a23040fe52f5ec74caf1d4aaad8a710";
    ecdsa_param.d = "218ee54a71ef2ccf012aca231fee28a2c665fc395ff5cd20bde9b8df59"
                    "8c282664abf9159c5b3923132983f945056d93";
    ecdsa_param.k = "c5d39b436d851d94691f5f4aa9ef447f7989d984f279ae8b091aef5449"
                    "ac062bcc0567740f914624ad5b99fc32f9af0b";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "ace953ae851f571d71779aa120915f27450b236da23e9106f8d0756"
                       "abdd25861937941228d225d5fb1aa1b1ebf759b1e326aeb3b6cd0cd"
                       "87edd2ab9f6a7ad67b63d2c501d6a550edb2e7c9d216cc8af78dd33"
                       "546af64d00abed4d0d2cfc5c9a7b5a055dbe8f7547902d185cf4693"
                       "7314832bc5c602419a82ab83dbd9d3bd5aff";
    ecdsa_param.d = "e6ab171f6937c000e144950801ad91023ae8e8476856c2592d9f7d5bb7"
                    "180fd729211803d39a412ead6c0be761cfa5d1";
    ecdsa_param.k = "05e9718aea9669c9e434f73866da5f252dec6d24c47a1c4ee3233450b6"
                    "ec626de9746ebe095b285558dfc89fc1b622fe";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "9635ab832240be95301bedb94c5aec169eedc198cbbdfedcf41e9b5"
                       "86143d829b4597a6b2a81902828332825fd84a785f187a3894e21bd"
                       "99d22c4f94dcf34453fc052f15ec64d1447c932cb38fcdd30b7be85"
                       "1963409c11881438cbaad7e96f9efbde317f2235d66af804477a5df"
                       "e9f0c51448383830050ecf228889f83631e1";
    ecdsa_param.d = "14acd516c7198798fd42ab0684d18df1cd1c99e304312752b3035bed65"
                    "35a8975dff8acfc2ba1675787c817b5bff6960";
    ecdsa_param.k = "7f623c103eaa9099a0462e55f80519c565adaeffcb57a29993f3a8a92e"
                    "63a560be8f0fb9d23dc80bff1064bb41abad79";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "d98b9a7d4fe9d0fd95de5056af164a8b7882cd34ab5bde83a2abb32"
                       "dc361eb56a479a3a6119db3b91dcad26a42d2206749567f0d97c34a"
                       "981a91fc734921821a429f6a53401743a5c406ba9d560f956203abc"
                       "9d1f32f1a13e7d7b290f75c95fdbf857ea597021461c06a3aacfa55"
                       "4ede3d69e4ff03bbbee5b7463ec77de2b3b2";
    ecdsa_param.d = "2e780550984f3a00cb1e412429b33493c6eb6cd86d12f9d80588c247dc"
                    "f567bd04296d2d4b24b889d9c54954b7f38f57";
    ecdsa_param.k = "b788ca82811b0d4e4841765c71eafaa1e575378beedcd3860d8b92db3d"
                    "070ac5aef7c425067860fbee6c50cf0c642bbb";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "1b4c754ac1c28dc415a71eac816bde68de7e8db66409af835838c5b"
                       "b2c605111108a3bf13606ed5d8ade5ed72e50503e0de664416393d1"
                       "78ea4eec834d8d6f15039847b410080fd5529b426e5aadd8451c20e"
                       "bd92d787921f33e147bcbeb327b104d4aab1157fc1df33e4d768404"
                       "b5ccb7110055c2508c600f429fd0c21b5784";
    ecdsa_param.d = "a24d0fe90808aecc5d90626d7e6da7c9be5dfd4e1233c7f0f71f1b7c1c"
                    "6fd318fafe18559c94718f044cf02ed5107cb1";
    ecdsa_param.k = "755d025509b73cf1ea8817beb772ad150b4c17a52378be187daffe3db0"
                    "158921e5e552d1ca3c85df28519939f3cb794d";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "3cd8c053741dd9f974c6c5dbf8a1e5728e9b5eafb1cbcfc3452f5fb"
                       "bda32a8c7564dee157e8d902c52514361da6d972934a56b3276e2a9"
                       "379e328e24282e0db697c5bc29090fc489ec46b7b188325dd4e9649"
                       "4c250de0f4a89fe2ccf919eaefcfb50c288113e6df92714feb7f46e"
                       "0822478c796d0f4ff3447a32997e892693ce";
    ecdsa_param.d = "1c172e25732555afee7ded67a496f3f11babc0875898619f4519c29321"
                    "e201e8ba1149f2c20b48e5efba235d58fea7c3";
    ecdsa_param.k = "08aec9a9e58bdc028805eb5dc86073d05fff1f5fb3fd17f510fc08f927"
                    "2d84ba7aa66b6f77d84fe6360bd538192bf01a";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "ed955dda6d9650124804d3deb6aeef900e520faf98b1ef6f14efcad"
                       "a7ca2433f09329b70897305e59c89024d76e466b28fe02cb2a9b12e"
                       "2478c66470259d7c282137a19e5a04ffadea55245c0f34a681593fe"
                       "dc42931d8b3321b3d82e9cc102cd00540ad311ec7bd8c9d06db21be"
                       "a4ca3dc74d98931ae0d40494aefc2345132c";
    ecdsa_param.d = "5b96555dbd602e71d4d5d3aee19fd1ea084ee23d4f55c10937056762bc"
                    "2015cbded2e898a487f5482ab7e1e971245907";
    ecdsa_param.k = "7ad6f4ffd2b429ba10c6f112f800cacf1ad508cf8eba880893bb9659c1"
                    "ddaaec57dcdc093a114500460d457bdde324f2";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "ce395b001da2a58e49691605d44af4206306f62f561bf2394060d2a"
                       "5591a350277166bed043819035f1e60b5b3fb5ae113ddd0473f8ef6"
                       "b2b050c472c2a264e1d8b3ca82a4f158c40f2d78d9ce5e5ea6de243"
                       "f2e1f13f47f6c6f403b270912c81c636be35b396ca58468b3fb60aa"
                       "83911d61441a0528d973bc31f965d4059080";
    ecdsa_param.d = "8df9c3c710a25192f3dea970910bb3784e3509874cccf4334823eb9f7a"
                    "8d05b067f2d812d61e878e24b093089a0b8245";
    ecdsa_param.k = "258dd05919735cd48627c9fe9fac5c252604aa7c2ae0460d7c1149cd96"
                    "b7bd2ba195ad393bf392a2499f06aead5ba050";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "ffefe316455ae4ffdb890bb804bf7d31424ea060ecacff419d0f713"
                       "4ff76ad434063c0ec0f8bb7059584d3a03f3625bb9e9f66ace1a47a"
                       "c4b8f3e76fc7c420c55edb1427d1fa15b387ad73d02b0595c4e7432"
                       "1be8822752230a0dcfb85d60bfa186da7623a8ec3eb1633f0a294b2"
                       "3ae87216b14ccee9ef56418dcfab9427371e";
    ecdsa_param.d = "6002cb01ad2ce6e7101665d47729c863b6435c3875de57a93f99da834f"
                    "73e3e6e2b3880e06de3e6bd1d51ea1807ab0d7";
    ecdsa_param.k = "6b9507fd2844df0949f8b67b6fde986e50173713ac03df2edf65cb3398"
                    "59321cd3a2b9aab8356f95dec62460ab19c822";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "304bccb718b3a9e12669913490cc5bcc1979287b56c628fad706c35"
                       "4241e88d10e81445a2853e3fc32ece094ba1abc3fdcab61da27f9a0"
                       "fca739371049fed462ee6b08fa31cde12720f8144a6f00ce9b1a7a6"
                       "eadd231f126717074b4efb5c72ce673ca5859000a436f67a338d698"
                       "759f12c461247c45a361fb6cb661fdbe6714";
    ecdsa_param.d = "d8559c3543afc6f7b3dc037a687bad2630283757ba7862fd23ed14e215"
                    "1a4cf5fed3d249268f780e0b96b6b46274a2d5";
    ecdsa_param.k = "4ad5a92b5b8e170b71c8a7ed419dc624c7680004562b8d16a37b6e639f"
                    "581ce81d5f0d98cce44d54c4e7136229148340";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "64f9f05c2805acf59c047b5f5d2e20c39277b6d6380f70f87b72327"
                       "a76170b872bfe4b25c451602acfb6a631bb885e2655aee8abe44f69"
                       "c90fb21ffde03cef2a452c468c6369867dfd8aa26ac24e16aa53b29"
                       "2375a8d8fbf988e302bf00088e4c061aa12c421d8fe3cbd7273b0e8"
                       "993701df1c59431f436a08b8e15bd123d133";
    ecdsa_param.d = "b9208cbfd186ddfa3efd5b71342ae1efb01a13ebc4c2a992a2cbee7254"
                    "b7846a4252ece1104b89d13d835911f8511224";
    ecdsa_param.k = "da706ab5f61531f2378b3c0a2b342108cd119eadaa88b859df64923bcc"
                    "fb0ec2393fd312826f65c15a6587d1d460015b";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp384r1 && dgst_len == SHA384_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0"
                       "c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de"
                       "654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb"
                       "4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f"
                       "2aaa6a00877fa9b45cadb8e648550b4c6cbe";
    ecdsa_param.d = "201b432d8df14324182d6261db3e4b3f46a8284482d52e370da41e6cbd"
                    "f45ec2952f5db7ccbce3bc29449f4fb080ac97";
    ecdsa_param.k = "dcedabf85978e090f733c6e16646fa34df9ded6e5ce28c6676a00f58a2"
                    "5283db8885e16ce5bf97f917c81e1f25c9c771";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "d768f41e6e8ec2125d6cf5786d1ba96668ac6566c5cdbbe407f7f20"
                       "51f3ad6b1acdbfe13edf0d0a86fa110f405406b69085219b5a234eb"
                       "db93153241f785d45811b3540d1c37424cc7194424787a51b796792"
                       "66484c787fb1ded6d1a26b9567d5ea68f04be416caf3be9bd2cafa2"
                       "08fe2a9e234d3ae557c65d3fe6da4cb48da4";
    ecdsa_param.d = "23d9f4ea6d87b7d6163d64256e3449255db14786401a51daa7847161bf"
                    "56d494325ad2ac8ba928394e01061d882c3528";
    ecdsa_param.k = "67ba379366049008593eac124f59ab017358892ee0c063d38f3758bb84"
                    "9fd25d867c3561563cac1532a323b228dc0890";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "6af6652e92a17b7898e40b6776fabaf0d74cf88d8f0ebfa6088309c"
                       "be09fac472eeac2aa8ea96b8c12e993d14c93f8ef4e8b547afe7ae5"
                       "e4f3973170b35deb3239898918c70c1056332c3f894cd643d2d9b93"
                       "c2561aac069577bbab45803250a31cd62226cab94d8cba7261dce9f"
                       "e88c210c212b54329d76a273522c8ba91ddf";
    ecdsa_param.d = "b5f670e98d8befc46f6f51fb2997069550c2a52ebfb4e5e25dd905352d"
                    "9ef89eed5c2ecd16521853aadb1b52b8c42ae6";
    ecdsa_param.k = "229e67638f712f57bea4c2b02279d5ccad1e7c9e201c77f6f01aeb81ea"
                    "90e62b44b2d2107fd66d35e56608fff65e28e4";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "b96d74b2265dd895d94e25092fb9262dc4f2f7a328a3c0c3da134b2"
                       "d0a4e2058ca994e3445c5ff4f812738e1b0c0f7a126486942a12e67"
                       "4a21f22d0886d68df2375f41685d694d487a718024933a7c4306f33"
                       "f1a4267d469c530b0fed4e7dea520a19dd68bf0203cc87cad652260"
                       "ed43b7b23f6ed140d3085875190191a0381a";
    ecdsa_param.d = "de5975d8932533f092e76295ed6b23f10fc5fba48bfb82c6cc714826ba"
                    "f0126813247f8bd51d5738503654ab22459976";
    ecdsa_param.k = "fc5940e661542436f9265c34bce407eff6364bd471aa79b90c906d923e"
                    "15c9ed96eea4e86f3238ea86161d13b7d9359d";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "7cec7480a037ff40c232c1d2d6e8cd4c080bbeecdaf3886fccc9f12"
                       "9bb6d202c316eca76c8ad4e76079afe622f833a16f4907e817260c1"
                       "fa68b10c7a151a37eb8c036b057ed4652c353db4b4a34b37c9a2b30"
                       "0fb5f5fcfb8aa8adae13db359160f70a9241546140e550af0073468"
                       "683377e6771b6508327408c245d78911c2cc";
    ecdsa_param.d = "11e0d470dc31fab0f5722f87b74a6c8d7414115e58ceb38bfcdced367b"
                    "eac3adbf1fe9ba5a04f72e978b1eb54597eabc";
    ecdsa_param.k = "e56904028226eb04f8d071e3f9cefec91075a81ca0fa87b44cae148fe1"
                    "ce9827b5d1910db2336d0eb9813ddba3e4d7b5";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "00ce978603229710345c9ad7c1c2dba3596b196528eea25bd822d43"
                       "ca8f76a024e29217703dd0652c8a615284fc3edcc1c5ad1c8d5a852"
                       "1c8e104c016a24e50c2e25066dcb56596f913b872767e3627aa3e55"
                       "ec812e9fdac7c2f1beade83aef093e24c9c953982adf431a776880a"
                       "e4583be158e11cdab1cbca3ad3a66900213d";
    ecdsa_param.d = "5c6bbf9fbcbb7b97c9535f57b431ed1ccae1945b7e8a4f1b032016b078"
                    "10bd24a9e20055c0e9306650df59ef7e2cd8c2";
    ecdsa_param.k = "03d23f1277b949cb6380211ad9d338e6f76c3eedac95989b91d0243cfb"
                    "734a54b19bca45a5d13d6a4b9f815d919eea77";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "54a255c18692c6162a46add176a0ae8361dcb8948f092d8d7bac83e"
                       "160431794d3b9812849bf1994bcdcfba56e8540c8a9ee5b93414548"
                       "f2a653191b6bb28bda8dc70d45cc1b92a489f58a2d54f85766cb3c9"
                       "0de7dd88e690d8ebc9a79987eee1989df35af5e35522f83d85c48dd"
                       "a89863171c8b0bf4853ae28c2ac45c764416";
    ecdsa_param.d = "ffc7dedeff8343721f72046bc3c126626c177b0e48e247f44fd61f8469"
                    "d4d5f0a74147fabaa334495cc1f986ebc5f0b1";
    ecdsa_param.k = "c3de91dbe4f777698773da70dd610ef1a7efe4dc00d734399c7dd10072"
                    "8006a502822a5a7ff9129ffd8adf6c1fc1211a";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "692a78f90d4f9d5aee5da536314a78d68c1feabbfe5d1ccea7f6059"
                       "a66c4b310f8051c411c409ccf6e19a0cbd8b8e100c48317fe8c6d4f"
                       "8a638b9551ce7ee178020f04f7da3001a0e6855225fb3c9b375e4ed"
                       "964588a1a41a095f3f476c42d52ffd23ce1702c93b56d4425d3befc"
                       "f75d0951b6fd5c05b05455bdaf205fe70ca2";
    ecdsa_param.d = "adca364ef144a21df64b163615e8349cf74ee9dbf728104215c532073a"
                    "7f74e2f67385779f7f74ab344cc3c7da061cf6";
    ecdsa_param.k = "a2da3fae2e6da3cf11b49861afb34fba357fea89f54b35ce5ed7434ae0"
                    "9103fe53e2be75b93fc579fedf919f6d5e407e";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "3b309bb912ab2a51681451ed18ad79e95d968abc35423a67036a02a"
                       "f92f575a0c89f1b668afe22c7037ad1199e757a8f06b281c33e9a40"
                       "bab69c9874e0bb680b905d909b9dc24a9fe89bb3d7f7d47082b2509"
                       "3c59754f8c19d1f81f30334a8cdd50a3cb72f96d4b3c305e60a439a"
                       "7e93aeb640dd3c8de37d63c60fb469c2d3ed";
    ecdsa_param.d = "39bea008ec8a217866dcbdb1b93da34d1d3e851d011df9ef44b7828b34"
                    "53a54aa70f1df9932170804eacd207e4f7e91d";
    ecdsa_param.k = "3c90cc7b6984056f570542a51cbe497ce4c11aeae8fc35e8fd6a0d9ade"
                    "b650e8644f9d1d5e4341b5adc81e27f284c08f";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "f072b72b8783289463da118613c43824d11441dba364c289de03ff5"
                       "fab3a6f60e85957d8ff211f1cb62fa90216fb727106f692e5ae0844"
                       "b11b710e5a12c69df3ed895b94e8769ecd15ff433762d6e8e94d8e6"
                       "a72645b213b0231344e2c968056766c5dd6b5a5df41971858b85e99"
                       "afbf859400f839b42cd129068efabeea4a26";
    ecdsa_param.d = "e849cf948b241362e3e20c458b52df044f2a72deb0f41c1bb0673e7c04"
                    "cdd70811215059032b5ca3cc69c345dcce4cf7";
    ecdsa_param.k = "32386b2593c85e877b70e5e5495936f65dc49553caef1aa6cc14d9cd37"
                    "0c442a0ccfab4c0da9ec311b67913b1b575a9d";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "cf4945350be8133b575c4ad6c9585e0b83ff1ed17989b6cd6c71b41"
                       "b5264e828b4e115995b1ae77528e7e9002ac1b5669064442645929f"
                       "9d7dd70927cb93f95edeb73e8624f4bc897ec4c2c7581cb626916f2"
                       "9b2d6e6c2fba8c59a71e30754b459d81b912a12798182bcff4019c7"
                       "bdfe929cc769bcc2414befe7d2906add4271";
    ecdsa_param.d = "d89607475d509ef23dc9f476eae4280c986de741b63560670fa2bd605f"
                    "5049f1972792c0413a5b3b4b34e7a38b70b7ca";
    ecdsa_param.k = "78613c570c8d33b7dd1bd1561d87e36282e8cf4843e7c344a2b2bb6a0d"
                    "a94756d670eeaffe434f7ae7c780f7cf05ca08";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "d9b5cf0b50416573ff3c63133275a18394dd4326be2041e8d97e6e4"
                       "e3855a4a177e9d26dfd223fe8aa74564edb49bd72de19916fb6f001"
                       "f44530d5c18e2c332bce1b7415df5927ece5f3824f34d174b963136"
                       "b53aef1fb78fb0c06a201a40b2db38e4d8216fc1e392a798c8ab4b3"
                       "a314496b7f1087804ebfa89bf96e9cdb80c0";
    ecdsa_param.d = "083e7152734adf342520ae377087a223688de2899b10cfcb34a0b36bca"
                    "500a4dfa530e2343e6a39da7ae1eb0862b4a0d";
    ecdsa_param.k = "28096ababe29a075fbdf894709a20d0fdedb01ed3eeacb642a33a0da6a"
                    "ed726e13caf6cf206792ec359f0c9f9b567552";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "9e4042d8438a405475b7dab1cd783eb6ce1d1bffa46ac9dfda622b2"
                       "3ac31057b922eced8e2ed7b3241efeafd7c9ab372bf16230f713464"
                       "7f2956fb793989d3c885a5ae064e85ed971b64f5f561e7ddb79d49a"
                       "a6ebe727c671c67879b794554c04de0e05d68264855745ef3c9567b"
                       "d646d5c5f8728b797c181b6b6a876e167663";
    ecdsa_param.d = "63578d416215aff2cc78f9b926d4c7740a77c142944e104aa7422b19a6"
                    "16898262d46a8a942d5e8d5db135ee8b09a368";
    ecdsa_param.k = "7b69c5d5b4d05c9950dc94c27d58403b4c52c004b80a80418ad3a89aab"
                    "c5d34f21926729e76afd280cc8ee88c9805a2a";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "0b14a7484a40b68a3ce1273b8a48b8fdb65ba900d98541c4bbd07b9"
                       "7e31bcc4c85545a03e9deab3c563f47a036ff60d0361684ba241b5a"
                       "a68bb46f440da22181ee328a011de98eff34ba235ec10612b07bdfa"
                       "6b3dc4ccc5e82d3a8d057e1862fef3def5a1804696f84699fda2ec4"
                       "175a54a4d08bcb4f0406fdac4eddadf5e29b";
    ecdsa_param.d = "ed4df19971658b74868800b3b81bc877807743b25c65740f1d6377542a"
                    "fe2c6427612c840ada31a8eb794718f37c7283";
    ecdsa_param.k = "d9b4cd1bdfa83e608289634dbfcee643f07315baf743fc91922880b55a"
                    "2feda3b38ddf6040d3ba10985cd1285fc690d5";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "0e646c6c3cc0f9fdedef934b7195fe3837836a9f6f263968af95ef8"
                       "4cd035750f3cdb649de745c874a6ef66b3dd83b66068b4335bc0a97"
                       "184182e3965c722b3b1aee488c3620adb835a8140e199f4fc83a88b"
                       "02881816b366a09316e25685217f9221157fc05b2d8d2bc85537218"
                       "3da7af3f0a14148a09def37a332f8eb40dc9";
    ecdsa_param.d = "e9c7e9a79618d6ff3274da1abd0ff3ed0ec1ae3b54c3a4fd8d68d98fb0"
                    "4326b7633fc637e0b195228d0edba6bb1468fb";
    ecdsa_param.k = "b094cb3a5c1440cfab9dc56d0ec2eff00f2110dea203654c70757254aa"
                    "5912a7e73972e607459b1f4861e0b08a5cc763";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp384r1 && dgst_len == SHA512_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "67d9eb88f289454d61def4764d1573db49b875cfb11e139d7eacc4b"
                       "7a79d3db3bf7208191b2b2078cbbcc974ec0da1ed5e0c10ec37f618"
                       "1bf81c0f32972a125df64e3b3e1d838ec7da8dfe0b7fcc911e43159"
                       "a79c73df5fa252b98790be511d8a732fcbf011aacc7d45d8027d50a"
                       "347703d613ceda09f650c6104c9459537c8f";
    ecdsa_param.d = "217afba406d8ab32ee07b0f27eef789fc201d121ffab76c8fbe3c2d352"
                    "c594909abe591c6f86233992362c9d631baf7c";
    ecdsa_param.k = "90338a7f6ffce541366ca2987c3b3ca527992d1efcf1dd2723fbd241a2"
                    "4cff19990f2af5fd6419ed2104b4a59b5ae631";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "45db86829c363c80160659e3c5c7d7971abb1f6f0d495709bba908d"
                       "7aa99c9df64b3408a51bd69aba8870e2aaff488ef138f3123cf9439"
                       "1d081f357e21906a4e2f311defe527c55e0231579957c51def507f8"
                       "35cceb466eb2593a509dcbee2f09e0dde6693b2bfe17697c9e86dd6"
                       "72f5797339cbe9ea8a7c6309b061eca7aef5";
    ecdsa_param.d = "0a3f45a28a355381a919372f60320d6610cfb69c3e318eb1607db3cadf"
                    "c42b728b77a6a9e9e333de9183c58933daf60f";
    ecdsa_param.k = "2a78e651623ba604c42cf094fc7d046629306f508853427ba091448800"
                    "d1092c041bb2323035fc9d19a8d44950f7dcc3";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "4672fce0721d37c5be166bffa4b30d753bcf104b9b414db994b3ed3"
                       "3f36af4935ea59a0bb92db66448b3f57dad4fc67cef10ce141bf82c"
                       "536be604b89a0bc0e8bca605b867880049d97142d30538fc543bd9d"
                       "4fab7fdbe2f703815cdb6361beb66acff764bc275f910d1662445b0"
                       "7b92830db69a5994857f53657ed5ca282648";
    ecdsa_param.d = "2e408c57921939f0e0fe2e80ce74a4fa4a1b4fa7ab070206298fe894d6"
                    "55be50e2583af9e45544b5d69c73dce8a2c8e7";
    ecdsa_param.k = "b10b6258afdde81f9c971cc1526d942e20cafac02f59fee10f98e99b86"
                    "74636bff1d84a6eaa49c0de8d8cfdc90d8ce84";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "9ae48fdd9bfc5cb0f4d4761e28b2073bda05a3e3fe82c212e66701d"
                       "c4573cc67a829b0f82d7520b1bf11db0c6d1743822bbe41bb0adbd7"
                       "222aa5fae70fbd1a31f2d4453a01c81e064d775388468be96f6063f"
                       "8673b7b8d4455fe1bd4c801ad5e625a015eaa4a1a18da490d2af864"
                       "2201eaba3c611cbd65f861d8e19ca82a1ee6";
    ecdsa_param.d = "1c285da72a8eb1c3c38faab8d3bb4e68dc95c797082b9a3991a21c1de5"
                    "4759071ecf2265fb1eff504ab24174bc6710cf";
    ecdsa_param.k = "2513075e02cc7fb3cff7b7adde46da31c5493749b5cf02758bd5b098a8"
                    "38bfd4d5e4c7fb8268bdc37e219c30efebe878";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "817d6a110a8fd0ca7b4d565558f68b59a156744d4c5aac5c6610c95"
                       "451793de2a756f774558c61d21818d3ebeeeb71d132da1c23a02f4b"
                       "305eccc5cd46bd21dfc173a8a91098354f10ffbb21bf63d9f4c3feb"
                       "231c736504549a78fd76d39f3ad35c36178f5c233742d2917d5611d"
                       "2073124845f1e3615b2ef25199a7a547e882";
    ecdsa_param.d = "9da37e104938019fbdcf247e3df879a282c45f8fb57e6655e36b47723a"
                    "f42bec3b820f660436deb3de123a21de0ca37b";
    ecdsa_param.k = "c8c18e53a9aa5915288c33132bd09323638f7995cd89162073984ed84e"
                    "72e07a37e18c4c023933eace92c35d10e6b1b6";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "464f10ec6fb229a51db5fd0e122f2cb8a9a022117e2987f4007bf55"
                       "65b2c16aba0714e2e3cdd0c100d55ac3017e36fc7501ad8309ab957"
                       "2aa65424c9eb2e580a119c55777676ec498df53ef6ae78fd8a98813"
                       "0ee0e6082bf1ef71cd4c946021018a8ca7154d13b174c638912613b"
                       "0bdb9001c302bf7e443ad2124ab2c1cce212";
    ecdsa_param.d = "0661ab3bf9f7bef51bec7dff758de289154557beb9ce18cc4b8cc09a87"
                    "1e8322af259cf188b593dc62f03a19e75f7f69";
    ecdsa_param.k = "84a87137edb6894f96c5a8e94a3765162034feb84dfea94e1c71411170"
                    "c285a80321ec7999e25861844143209804882c";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "4e3e0fb96320ddccde8b463c273654c4f7164920b1d63430921d2e8"
                       "08dee403e6420eedda0a557b911d00736a4f8798dd4ef26673efd6d"
                       "190988ad4929ec64f8685cfb76070a36cd6a3a4bf2f54fb08a349d4"
                       "4642b6f614043fef9b2813b63457c76537d23da7b37310334f7ba76"
                       "edf1999dad86f72aa3446445a65952ac4e50";
    ecdsa_param.d = "66e7cfdeb7f264cf786e35210f458c32223c3a12a3bc4b63d53a5776bc"
                    "9b069928452484f6241caa3781fd1a4109d4db";
    ecdsa_param.k = "2fa266f5cce190eb77614933ca6a55121ad8bae168ff7a9043d96d13b5"
                    "ca2fe70101ff9fe1e2b2cd7413e6aa8f49abde";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "c466b6b6baf7e6ffa876ec06105e2d43534e0517c07b1c4c9fb67ba"
                       "81ce09525a7721ec3c290f2b1f65b6463d41598e7a25b2238501629"
                       "953a5ca955b644354fb6856733a2e5bb8f5bc21a0c803493f5539f9"
                       "fb83aab3dba2c982989c2270c61ab244b68bfe1b948d00c2ed975e0"
                       "9c29b5f8a7effcad8652a148cc880d503217";
    ecdsa_param.d = "92c2f7ee64af86d003ab484e12b82fcf245fc330761057fec5b7af8f7e"
                    "0a2d85b468c21d171460fcb829cae7b986316d";
    ecdsa_param.k = "6ec81fb74f8725ba225f317264460ee300cfd2f02092000989acbdad47"
                    "99cf55c244a65c557113328fe20282e6badb55";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "feac892b7720af80b3c9eede51e923f18d3d0c5de4c31f4aa75e36d"
                       "f7c7c2fd8f41778851a24b69e67dccb65e159dd5c383243bad7cfed"
                       "cc5e85c8a01c34b0b94ba8e07e4c024c09d279b3731e8b62f9562d3"
                       "c4f5042567efe42a9d0eaaabab28bc6f11232fc8ceaaf4518d9f3b2"
                       "bebf020294496b7f6b879e69503f75fecd3d";
    ecdsa_param.d = "15347caaad1067f1848a676bd0a8c52021ae604b79d02775a0459226e0"
                    "391a3acd26653c916fcfe86149fb0ee0904476";
    ecdsa_param.k = "1a2d224db4bb9c241ca5cab18920fad615fa25c1db0de0f024cb3ace0d"
                    "11ef72b056885446659f67650fdff692517b1c";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "cf2982e3bf174ce547741b969403cd11e9553067e6af8177d89511a"
                       "0eb040db924530bdba65d8b1ff714228db0737c1756f509e1506014"
                       "a10736e65be2f91980a73891496e90ff2714a3601c7565cdcef5a39"
                       "5e2e0e1652f138d90d61eaa9cba993b823245647f6e07cec9b8b444"
                       "9cd68a29741cd1579c66e548ca0d0acf33aa";
    ecdsa_param.d = "ac1cb5e59bda2eff3413a3bab80308f9fb32c595283c795de4c17fdae8"
                    "d4647b5f108fd0801aee22adb7db129283b5aa";
    ecdsa_param.k = "8053a46e875f446056b06d4318fa3e8977622de7207cbf0996bf35b0e9"
                    "b19aaa507f642bcf0be9f048f1af09806f6946";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "bf9fdd4107ef5a6070108771ac9eee4f0c8043bf0d04db772a47294"
                       "f4137e2439d94b337114b074e57e0cb78d0ccf352a2833e9788ee2a"
                       "1a9ffeacd34f38fcefb86653d70c7dadd4cf6548d608e70acdef6c7"
                       "530974b92c813798add659752a8c72b05e1ad9c65c21834ce6fbe49"
                       "d8a1426b5a54270794436d284364fac6ec1a";
    ecdsa_param.d = "205f1eb3dfacff2bdd8590e43e613b92512d6a415c5951bda7a6c37db3"
                    "aae39b9b7ec6edd256609e75373419087fa71f";
    ecdsa_param.k = "ecd395c5d8b7d6e6b2b19644e0d2e6086c912c6a0f5b8ed4b94b7290b6"
                    "5852c9741ce8eeb08d8751ead8a183e17d76c6";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "5d634fb39a2239256107dc68db19751540b4badac9ecf2fce644724"
                       "401d6d632b3ae3b2e6d05746b77ddc0c899878032248c263eda08d3"
                       "d004d35952ad7a9cfe19343d14b37f9f632245e7b7b5fae3cb31c52"
                       "31f82b9f1884f2de7578fbf156c430257031ba97bc6579843bc7f59"
                       "fcb9a6449a4cd942dffa6adb929cf219f0ad";
    ecdsa_param.d = "e21e3a739e7ded418df5d3e7bc2c4ae8da76266a1fc4c89e5b09923db8"
                    "0a72217f1e96158031be42914cf3ee725748c1";
    ecdsa_param.k = "d06bea06b25e6c30e866b1eb0657b45673e37b709013fb28fd7373afc8"
                    "277cbc861354f821d0bd1927e52ec083a0f41f";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "c9b4ff721b3e886f0dc05856ffff0aabb64a8504b1746a47fdd73e6"
                       "b7ebc068f06ac7ffa44c757e4de207fc3cbfaf0469d3ac6795d4063"
                       "0bcafe8c658627e4bc6b86fd6a2135afbc18ccc8e6d0e1e86016930"
                       "ca92edc5aa3fbe2c57de136d0ea5f41642b6a5d0ddeb380f2454d76"
                       "a16639d663687f2a2e29fb9304243900d26d";
    ecdsa_param.d = "93434d3c03ec1da8510b74902c3b3e0cb9e8d7dccad37594d28b93e065"
                    "b468d9af4892a03763a63eae060c769119c23c";
    ecdsa_param.k = "13d047708ae5228d6e3bbada0e385afdb3b735b31123454fdf40afe3c3"
                    "6efed563fd2cce84dcc45c553b0993d9ca9ec3";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "db2ad659cf21bc9c1f7e6469c5f262b73261d49f7b1755fc137636e"
                       "8ce0202f929dca4466c422284c10be8f351f36333ebc04b1888cba2"
                       "17c0fec872b2dfc3aa0d544e5e06a9518a8cfe3df5b20fbcb14a9bf"
                       "218e3bf6a8e024530a17bab50906be34d9f9bba69af0b11d8ed426b"
                       "9ec75c3bd1f2e5b8756e4a72ff846bc9e498";
    ecdsa_param.d = "e36339ddbe8787062a9bc4e1540690915dd2a2f11b3fe9ee946e281a0a"
                    "2cbed426df405ed9cb0eca42f85443efd09e0c";
    ecdsa_param.k = "2226f7329378cecd697f36ae151546643d67760856854661e31d424fae"
                    "662da910e2157da9bb6dfbe3622296e0b5710c";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "dbd8ddc02771a5ff7359d5216536b2e524a2d0b6ff180fa29a41a88"
                       "47b6f45f1b1d52344d32aea62a23ea3d8584deaaea38ee92d1314fd"
                       "b4fbbecdad27ac810f02de0452332939f644aa9fe526d313cea81b9"
                       "c3f6a8dbbeafc899d0cdaeb1dca05160a8a039662c4c845a3dbb07b"
                       "e2bc8c9150e344103e404411668c48aa7792";
    ecdsa_param.d = "5da87be7af63fdaf40662bd2ba87597f54d7d52fae4b298308956cddbe"
                    "5664f1e3c48cc6fd3c99291b0ce7a62a99a855";
    ecdsa_param.k = "1b686b45a31b31f6de9ed5362e18a3f8c8feded3d3b251b134835843b7"
                    "ae8ede57c61dc61a30993123ac7699de4b6eac";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp521r1 && dgst_len == SHA224_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "58ec2b2ceb80207ff51b17688bd5850f9388ce0b4a4f7316f5af6f5"
                       "2cfc4dde4192b6dbd97b56f93d1e4073517ac6c6140429b5484e266"
                       "d07127e28b8e613ddf65888cbd5242b2f0eee4d5754eb11f25dfa5c"
                       "3f87c790de371856c882731a157083a00d8eae29a57884dbbfcd989"
                       "22c12cf5d73066daabe3bf3f42cfbdb9d853";
    ecdsa_param.d = "1d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a9"
                    "6d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364ae"
                    "ae13c983e9fae46";
    ecdsa_param.k = "141f679033b27ec29219afd8aa123d5e535c227badbe2c86ff6eafa511"
                    "6e9778000f538579a80ca4739b1675b8ff8b6245347852aa524fe9aad7"
                    "81f9b672e0bb3ff";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "2449a53e0581f1b56d1e463b1c1686d33b3491efe1f3cc0443ba05d"
                       "65694597cc7a2595bda9cae939166eb03cec624a788c9bbab69a39f"
                       "b6554649131a56b26295683d8ac1aea969040413df405325425146c"
                       "1e3a138d2f4f772ae2ed917cc36465acd66150058622440d7e77b3a"
                       "d621e1c43a3f277da88d850d608079d9b911";
    ecdsa_param.d = "17e49b8ea8f9d1b7c0378e378a7a42e68e12cf78779ed41dcd29a090ae"
                    "7e0f883b0d0f2cbc8f0473c0ad6732bea40d371a7f363bc6537d075bd1"
                    "a4c23e558b0bc73";
    ecdsa_param.k = "1dc3e60a788caa5f62cb079f332d7e5c918974643dca3ab3566a599642"
                    "cd84964fbef43ce94290041fe3d2c8c26104d9c73a57a7d47246132425"
                    "31083b49e255f33";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "7ba05797b5b67e1adfafb7fae20c0c0abe1543c94cee92d5021e1ab"
                       "c57720a6107999c70eacf3d4a79702cd4e6885fa1b7155398ac729d"
                       "1ed6b45e51fe114c46caf444b20b406ad9cde6b9b2687aa645b46b5"
                       "1ab790b67047219e7290df1a797f35949aaf912a0a8556bb21018e7"
                       "f70427c0fc018e461755378b981d0d9df3a9";
    ecdsa_param.d = "135ea346852f837d10c1b2dfb8012ae8215801a7e85d4446dadd993c68"
                    "d1e9206e1d8651b7ed763b95f707a52410eeef4f21ae9429828289eaea"
                    "1fd9caadf826ace";
    ecdsa_param.k = "0c24acc1edb3777212e5b0bac744eadf4eda11fa150753b355bf96b189"
                    "e6f57fc02284bb22d8b3cd8bba7a09aae9f4ea955b382063425a6f8da2"
                    "f99b9647b147172";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "716dabdb22a1c854ec60420249905a1d7ca68dd573efaff7542e76f"
                       "0eae54a1828db69a39a1206cd05e10e681f24881b131e042ed9e19f"
                       "5995c253840e937b809dfb8027fed71d541860f318691c13a2eb514"
                       "daa5889410f256305f3b5b47cc16f7a7dad6359589b5f4568de4c4a"
                       "ae2357a8ea5e0ebaa5b89063eb3aa44eb952";
    ecdsa_param.d = "1393cb1ee9bfd7f7b9c057ecc66b43e807e12515f66ed7e9c9210ba151"
                    "4693965988e567fbad7c3f17231aacee0e9b9a4b1940504b1cd4fd5edf"
                    "aa62ba4e3e476fc";
    ecdsa_param.k = "1d98619bdc04735d30c222fc67da82c069aea5f449af5e8c4db10c1786"
                    "c0cb9e6f2cc0bb66fa6be18c485570d648dafcd0a973c43d5c94e9a9da"
                    "cbd3170e53fa2a0";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "9cc9c2f131fe3ac7ea91ae6d832c7788cbbf34f68e839269c336cee"
                       "f7bef6f20c0a62ea8cc340a333a3002145d07eba4cf4026a0c4b26b"
                       "0217a0046701de92d573d7c87a386a1ea68dc80525b7dcc9be41b45"
                       "1ad9f3d16819e2a0a0b5a0c56736da3709e64761f97cae2399de2a4"
                       "022dc4c3d73c7a1735c36dbde86c4bc5b6f7";
    ecdsa_param.d = "179fa164e051c5851e8a37d82c181e809a05fea9a3f083299b22684f59"
                    "aa27e40dc5a33b3f7949338764d46bfe1f355134750518b856d98d9167"
                    "ef07aac3092c549";
    ecdsa_param.k = "16d9704c0cee791f2938bb2a8a595752a3635c2f557efeecefd719414b"
                    "5f2aaf846080f582c76eae7a8fddf81859b49d0131c212524d55defa67"
                    "dca1a9a28ca400f";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "14c69f8d660f7a6b37b13a6d9788eff16311b67598ab8368039ea1d"
                       "9146e54f55a83b3d13d7ac9652135933c68fafd993a582253be0dee"
                       "a282d86046c2fb6fd3a7b2c80874ced28d8bed791bd4134c796bb7b"
                       "af195bdd0dc6fa03fdb7f98755ca063fb1349e56fd0375cf94774df"
                       "4203b34495404ebb86f1c7875b85174c574c";
    ecdsa_param.d = "13dabca37130ba278eae2b3d106b5407711b0d3b437fbf1c952f077357"
                    "1570764d2c7cb8896a8815f3f1975b21adc6697898e5c0a4242092fc1b"
                    "80db819a4702df4";
    ecdsa_param.k = "0401187c8b89945a1e48cda9ee52167789f4121e67482a7ac797899f5d"
                    "3d2e623aed31e4adae08a8d43e69028fa074d2650317cbc765f6ed191c"
                    "f0317b4bae57881";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "8d8e75df200c177dbfe61be61567b82177ea5ec58e2781168d2277d"
                       "2fd42668f01248ca3eb29ffa2689b12ae40f9c429532b6d2e1f1589"
                       "1322b825a0a072a1c68fa09e78cfdef3e95ed6fdf7233a43cb68236"
                       "560d49a3278f0b3f47cb08f475bd9ab2f60755ea4a1767de9313b71"
                       "a1b9ea87ef33f34682efbda263b0f8cc2f52";
    ecdsa_param.d = "198681adbde7840d7ccd9cf1fb82056433fb4dd26bddf909af7b3b99da"
                    "1ca2c05c8d4560ecd80ba68f376f8b487897e374e99a9288ed7e3645cc"
                    "0d00a478aae8d16";
    ecdsa_param.k = "19d2d74ad8ee2d85048f386998a71899ef6c960b4ab324e5fd1c0a076c"
                    "5a632fd0009500076522e052c5c9806eef7056da48df6b16eb71cdf0f1"
                    "838b0e21715fce0";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "10631c3d438870f311c905e569a58e56d20a2a560e857f0f9bac2bb"
                       "7233ec40c79de145294da0937e6b5e5c34fff4e6270823e5c8553c0"
                       "7d4adf25f614845b2eac731c5773ebbd716ab45698d156d04385994"
                       "5de57473389954d223522fbafecf560b07ef9ba861bcc1df9a7a89c"
                       "dd6debf4cd9bf2cf28c193393569ccbd0398";
    ecdsa_param.d = "08c4c0fd9696d86e99a6c1c32349a89a0b0c8384f2829d1281730d4e9a"
                    "f1df1ad5a0bcfccc6a03a703b210defd5d49a6fb82536f88b885776f0f"
                    "7861c6fc010ef37";
    ecdsa_param.k = "189801432cba9bf8c0763d43b6ec3b8636e62324587a4e27905b09a58e"
                    "4aa66d07d096dbce87824e837be1c243dd741f983c535a5dd2f077aac8"
                    "beee9918258d3cb";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "80aad6d696cbe654faa0d0a24d2f50d46e4f00a1b488ea1a98ed06c"
                       "44d1d0c568beb4ab3674fc2b1d2d3da1053f28940e89ba1244899e8"
                       "515cabdd66e99a77df31e90d93e37a8a240e803a998209988fc829e"
                       "239150da058a300489e33bf3dcdaf7d06069e74569fee77f4e3875d"
                       "0a713ccd2b7e9d7be62b34b6e375e84209ef";
    ecdsa_param.d = "1466d14f8fbe25544b209c5e6a000b771ef107867e28ed489a42015119"
                    "d1aa64bff51d6b7a0ac88673bbc3618c917561cff4a41cdb7c2833dab5"
                    "ebb9d0ddf2ca256";
    ecdsa_param.k = "160d04420e0d31b0df476f83393b1f9aff68389cc3299e42ef348d9764"
                    "6f7531a722b66ddfb9501bbb5c4a41d84c78be7233b11489bceb817d23"
                    "060e6017433fab8";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "8a7792a2870d2dd341cd9c4a2a9ec2da753dcb0f692b70b64cef2e2"
                       "2071389c70b3b188dea5f409fb435cbd09082f59de6bc2ff9e65f91"
                       "b7acc51e6e7f8e513148cb3c7c4664f227d5c704626b0fda447aa87"
                       "b9d47cd99789b88628eb642ed250312de5ba6b25f3d5342a3cbb7eb"
                       "d69b0044ee2b4c9ba5e3f5195afb6bea823d";
    ecdsa_param.d = "01a99fcf54c9b85010f20dc4e48199266c70767e18b2c618044542cd0e"
                    "23733817776a1a45dbd74a8e8244a313d96c779f723013cd88886cb7a0"
                    "8ef7ee8fdd862e7";
    ecdsa_param.k = "14fafd60cb026f50c23481867772411bb426ec6b97054e025b35db74fe"
                    "8ea8f74faa2d36e7d40b4652d1f61794878510b49b7b4fe4349afccd24"
                    "fc45fec2fd9e9e7";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "f971bcd396efb8392207b5ca72ac62649b47732fba8feaa8e84f7fb"
                       "36b3edb5d7b5333fbfa39a4f882cb42fe57cd1ace43d06aaad33d06"
                       "03741a18bc261caa14f29ead389f7c20536d406e9d39c34079812ba"
                       "26b39baedf5feb1ef1f79990496dd019c87e38c38c486ec1c251da2"
                       "a8a9a57854b80fcd513285e8dee8c43a9890";
    ecdsa_param.d = "1b6015d898611fbaf0b66a344fa18d1d488564352bf1c2da40f52cd997"
                    "952f8ccb436b693851f9ccb69c519d8a033cf27035c27233324f10e996"
                    "9a3b384e1c1dc73";
    ecdsa_param.k = "1a88667b9bdfe72fb87a6999a59b8b139e18ef9273261549bc394d884d"
                    "b5aa64a0bc7c7d38a8ef17333478d2119d826e2540560d65f52b9a6dc9"
                    "1be1340cfd8f8f8";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "ec0d468447222506b4ead04ea1a17e2aa96eeb3e5f066367975dbae"
                       "a426104f2111c45e206752896e5fa7594d74ed184493598783cb807"
                       "9e0e915b638d5c317fa978d9011b44a76b28d752462adf305bde321"
                       "431f7f34b017c9a35bae8786755a62e746480fa3524d398a6ff5fdc"
                       "6cec54c07221cce61e46fd0a1af932fa8a33";
    ecdsa_param.d = "05e0d47bf37f83bcc9cd834245c42420b68751ac552f8a4aae8c24b606"
                    "4ae3d33508ecd2c17ec391558ec79c8440117ad80e5e22770dac7f2017"
                    "b755255000c853c";
    ecdsa_param.k = "18afea9a6a408db1e7a7bb1437a3d276f231eacfc57678bfa229d78681"
                    "cbe4e800e6065332a3128db65d3aa446bb35b517dca26b02e106e13118"
                    "81a95b0302d15e8";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "d891da97d2b612fa6483ee7870e0f10fc12a89f9e33d636f587f72e"
                       "0049f5888782ccde3ea737e2abca41492bac291e20de5b84157a43c"
                       "5ea900aef761006a4471072ab6ae6d515ffe227695d3ff2341355b8"
                       "398f72a723ae947f9618237c4b6642a36974860b452c0c6202688bc"
                       "0814710cbbff4b8e0d1395e8671ae67ada01";
    ecdsa_param.d = "1804ab8f90ff518b58019a0b30c9ed8e00326d42671b71b067e6f815ac"
                    "6752fa35016bd33455ab51ad4550424034419db8314a91362c28e29a80"
                    "fbd193670f56ace";
    ecdsa_param.k = "042d7c36fec0415bc875deb0fab0c64548554062e618aee3aa6670ffd6"
                    "8ab579fe620d3a9316357267fd3111c0ed567dca663acd94b646d2ba07"
                    "71953cd9690ef42";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "924e4afc979d1fd1ec8ab17e02b69964a1f025882611d9ba57c7721"
                       "75926944e42c68422d15f9326285538a348f9301e593e02c35a9817"
                       "b160c05e21003d202473db69df695191be22db05615561951867f84"
                       "25f88c29ba8997a41a2f96b5cee791307369671543373ea91d5ed9d"
                       "6a34794d33305db8975b061864e6b0fe775f";
    ecdsa_param.d = "0159bff3a4e42b133e20148950452d99681de6649a56b904ee3358d6dd"
                    "01fb6c76ea05345cb9ea216e5f5db9ecec201880bdff0ed02ac28a6891"
                    "c164036c538b8a8";
    ecdsa_param.k = "14b8a30f988cefdc0edec59537264edb0b697d8c4f9e8507cf72bc01c7"
                    "61304bd2019da1d67e577b84c1c43dd034b7569f16635a771542b03997"
                    "37025b8d817e1c3";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "c64319c8aa1c1ae676630045ae488aedebca19d753704182c4bf3b3"
                       "06b75db98e9be438234233c2f14e3b97c2f55236950629885ac1e0b"
                       "d015db0f912913ffb6f1361c4cc25c3cd434583b0f7a5a9e1a549aa"
                       "523614268037973b65eb59c0c16a19a49bfaa13d507b29d5c7a146c"
                       "d8da2917665100ac9de2d75fa48cb708ac79";
    ecdsa_param.d = "17418dfc0fc3d38f02aa06b7df6afa9e0d08540fc40da2b459c727cff0"
                    "52eb0827bdb3d53f61eb3033eb083c224086e48e3eea7e85e31428ffe5"
                    "17328e253f166ad";
    ecdsa_param.k = "1211c8824dcbfa0e1e15a04779c9068aed2431daeac298260795e6a804"
                    "01f11f6d52d36bcee3cfa36627989c49d11475163aa201d2cd4c539414"
                    "4a6bb500bbaf02b";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp521r1 && dgst_len == SHA256_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "8ab8176b16278db54f84328ae0b75ef8f0cd18afdf40c04ad0927ed"
                       "0f6d9e47470396c8e87cde7a9be2ffbfe6c9658c88b7de4d5821111"
                       "19c433b2e4a504493f0a1166e3a3ea0d7b93358f4a297d63f65a5e7"
                       "52f94e2ee7f49ebcc742fa3eb03a617d00c574245b77a20033854d8"
                       "2964b2949e2247637239ab00baf4d170d97c";
    ecdsa_param.d = "1e8c05996b85e6f3f875712a09c1b40672b5e7a78d5852de01585c5fb9"
                    "90bf3812c3245534a714389ae9014d677a449efd658254e610da8e6cad"
                    "33414b9d33e0d7a";
    ecdsa_param.k = "0dc8daaacddb8fd2ff5c34a5ce183a42261ad3c64dbfc095e58924364d"
                    "c47ea1c05e2599aae917c2c95f47d6bb37da008af9f55730ddbe4d8ded"
                    "24f9e8daa46db6a";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "c4bc2cec829036469e55acdd277745034e4e3cc4fcd2f50ec8bd890"
                       "55c19795a1e051ccf9aa178e12f9beab6a016a7257e391faa536eaa"
                       "5c969396d4e1ade36795a82ebc709d9422de8497e5b68e7292538d4"
                       "ccdc6dd66d27a3ece6a2844962b77db073df9489c9710585ba03d53"
                       "fa430dbc6626dc03b61d53fc180b9af5dea6";
    ecdsa_param.d = "0b65bf33b2f27d52cbfabcadce741e691bf4762089afd37964de1a0ded"
                    "a98331bf8c74020a14b52d44d26e2f6fa7bcddbe83be7db17a0c8a1b37"
                    "6469cf92c6da27c";
    ecdsa_param.k = "14aeb96c57d99677a1f5e4588064215e7e9af4027bfb8f31ff6126dbf3"
                    "41b8e6f719465e4273e91ba32670feca802549808322b7ee108bb20653"
                    "cf20f93284d365f";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "1c1b641d0511a0625a4b33e7639d7a057e27f3a7f818e67f593286c"
                       "8a4c827bb1f3e4f399027e57f18a45403a310c785b50e5a03517c72"
                       "b45ef8c242a57b162debf2e80c1cf6c7b90237aede5f4ab1fcaf818"
                       "7be3beb524c223cc0ceff24429eb181a5eea364a748c713214880d9"
                       "76c2cd497fd65ab3854ad0d6c2c1913d3a06";
    ecdsa_param.d = "02c4e660609e99becd61c14d043e8b419a663010cc1d8f9469897d7d0a"
                    "4f076a619a7214a2a9d07957b028f7d8539ba7430d0b9a7de08beeeae8"
                    "452d7bb0eac669d";
    ecdsa_param.k = "1f875bbf882cd6dd034a87916c7b3ba54b41b2ea2ce84ebaf4e393fcf7"
                    "291fee09dec2b5bb8b6490997c9e62f077c34f0947fe14cec99b906dd6"
                    "bf0b5d301e75ca1";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "adb5f069b2b501a3ebb83d4f1808eb07710ac4a7b12532996855a20"
                       "bcc54b2f76812915f632163c3654ff13d187d007152617cf8592001"
                       "94b59c5e81fc6cc9eb1ceb75d654050f260caa79c265254089270cc"
                       "d02607fdcf3246119738c496dc3a4bd5d3be15789fc3d29a08d6d92"
                       "1febe2f40aef286d5d4330b07198c7f4588e";
    ecdsa_param.d = "17c3522007a90357ff0bda7d3a36e66df88ca9721fb80e8f63f50255d4"
                    "7ee819068d018f14c6dd7c6ad176f69a4500e6f63caf5cf780531004f8"
                    "5009c69b9c1230c";
    ecdsa_param.k = "18388a49caeda35859ef02702c1fd45ff26991998bd9d5e189c12c36cd"
                    "ae3f642ddd4a79561bd1d3e1cd9359de8f5c9e1604a312d207a27b08a6"
                    "033f2741794ced5";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "f253484d121d1ce8a88def6a3e9e78c47f4025ead6f73285bf90647"
                       "102645b0c32d4d86742a50b8b7a42d5f6156a6faf588212b7dc72c3"
                       "ffd13973bdba732b554d8bffc57d04f8167aef21ee941ee6ffb6cce"
                       "0f49445bd707da8deb35dca650aaf761c3aa66a5ebccddd15aee212"
                       "93f63061a7f4bfc3787c2cd62c806a1a9985";
    ecdsa_param.d = "0c4dad55871d3bd65b016d143ddd7a195cc868b3048c8bbcb143562203"
                    "6bdb5e0dec7178ca0138c610238e0365968f6ddd191bbfacc919480880"
                    "44d9966f652ff25";
    ecdsa_param.k = "05577108f4187a173e5c29e927a8fc8f5ffd37e184254a6e381ff10189"
                    "55aec91a35f30085e8cee6a7555c10f9efdce26d62f2b4b52dfdbaeafc"
                    "3a30983e2d50d5b";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "33bab1c369c495db1610965bc0b0546a216e8dd00cd0e602a605d40"
                       "bc8812bbf1ffa67143f896c436b8f7cf0bed308054f1e1ff77f4d0a"
                       "13c1e831efbd0e2fcfb3eadab9f755f070ba9aeaceb0a5110f2f8b0"
                       "c1f7b1aa96a7f2d038a1b72e26400819b1f73d925ea4e34d6acaf59"
                       "d0a461a34ce5d65c9c937a80e844e323a16d";
    ecdsa_param.d = "03d4749fadcc2008f098de70545a669133c548ce0e32eec1276ff531bc"
                    "ff53533144555728ad8906d17f091cc0514571691107350b6561858e90"
                    "dbe19633aaf31bf";
    ecdsa_param.k = "1fbb4de337b09e935a6dc6215ffcfcb85d236cc490585e73251a8b8bac"
                    "37cfa36c5d1df5f4536d33659be1e7a442529a783452f7efda74a4f661"
                    "b6a127f9248aaf7";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "08c8b7faaac8e1154042d162dca1df0f66e0001b3c5ecf49b6a4334"
                       "ce4e8a754a1a8e4daf8ec09cf1e521c96547aed5172ef852e82c03c"
                       "ddd851a9f992183ac5199594f288dbcc53a9bb6128561ff3236a7b4"
                       "b0dce8eaf7d45e64e782955ee1b690ce6a73ece47dc4409b690de6b"
                       "7928cbe60c42fc6a5ddf1d729faf1cc3885e";
    ecdsa_param.d = "096a77b591bba65023ba92f8a51029725b555caf6eff129879d28f6400"
                    "e760439d6e69ce662f6f1aecf3869f7b6057b530a3c6ff8ed9e86d5944"
                    "f583ee0b3fbb570";
    ecdsa_param.k = "13aa7b0471317a2a139c2f90df1c40d75e5a8a830fbaf87030fffdb2ef"
                    "6f2c93d1310c9ed7fe9d7bcd4fe46537ff2495bc9c4f0aaff11461f5e4"
                    "bebbfbce9a8740a";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "ba74eed74282811631bd2069e862381e4e2a1e4e9a357b1c159a9ce"
                       "69786f864b60fe90eeb32d8b72b099986fc594965a33285f7185b41"
                       "5df58fead7b8b50fc60d073680881d7435609ad1d22fd21e789b673"
                       "0e232b0d2e888889fb82d6ad0337ab909308676164d4f47df44b211"
                       "90eca8ba0f94995e60ad9bb02938461eee61";
    ecdsa_param.d = "015152382bfd4f7932a8668026e705e9e73daa8bade21e80ea62cf91bd"
                    "2448ebc4487b508ca2bdaaf072e3706ba87252d64761c6885a65dcafa6"
                    "4c5573c224ae9e6";
    ecdsa_param.k = "0d03506999f5cc9ec3304072984a20a9c64a22ad9b418495ca904f4bbd"
                    "dc96e76d34672cb52763339d3f3bc5b1701c00a675b972797e3a086314"
                    "da1a8d338436566";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "dc71f171a28bdc30968c39f08f999b88dc04c550e261ecf1124d67f"
                       "05edeae7e87fe9b8135a96fe2bc3996a4f47213d9d191184a76bd63"
                       "10e1ee5cb67ea7fc3ef6f641a0ba165198040fa668192b75a4754fc"
                       "02c224bd4a74aade5a8c814adf151c2bfeda65165a04ef359e39847"
                       "c84e312afb66d4cd1db50d41ef3fe5f31296";
    ecdsa_param.d = "1750ff0ca0c166560b2034bc5760fe0b3915340bc43216e9de0c1d4a76"
                    "550e8b2036e8b874230f8d29354aed43e183610f24fd4abd4b0be2f111"
                    "dae942bd7a121f7";
    ecdsa_param.k = "023645023d6bdf20652cdce1185c4ef225c66d54f18632d99ccf743bf5"
                    "54d04c214c88ce52a4f71ec75c899ad1b3c07c34112ca20b55c217ff1d"
                    "72c9528e2774ce8";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "b895788d7828aaeace4f6b61a072ffa344d8ea324962ba6dab5efda"
                       "93f65bf64a0f2ac6d5721d03ee70e2aef21cdba69fd29040199160e"
                       "3a293b772ffb961ed694a8dc82800dab79367a4809a864e4aff6bc8"
                       "37aaa868e952b771b76591c0bb82249034e3208e593d85973d3fea7"
                       "53a95b16e221b2561644535c0131fe834ae7";
    ecdsa_param.d = "023048bc16e00e58c4a4c7cc62ee80ea57f745bda35715510ed0fc29f6"
                    "2359ff60b0cf85b673383b87a6e1a792d93ab8549281515850fa24d6a2"
                    "d93a20a2fff3d6e";
    ecdsa_param.k = "06099d2667f06c58798757632d07d8b3efbe9c1323efb0c244be6b12b3"
                    "b163ba1b7cf5246c98dcc0771665a66696d687af5f28ed664fd87d5093"
                    "df6427523d4db84";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "2c5bd848c476e34b427cfe5676692e588e1957957db7b5704492bd0"
                       "2104a38216535607f5d092dc40020130c04a3aaf0f1c52409834926"
                       "d69a05d3f3188187a71d402a10ba34eac8629b4c6359b1095f30f71"
                       "0219298bf06b9f19bfc299981d7e251ca232a0a85338a7e02464731"
                       "d1b25d4a1f68baf97064516590644820c998";
    ecdsa_param.d = "02b8b866ce4503bb40ffc2c3c990465c72473f901d6ebe6a119ca49fce"
                    "c8221b3b4fa7ec4e8e9a10dbd90c739065ad6a3a0dd98d1d6f6dcb0720"
                    "f25a99357a40938";
    ecdsa_param.k = "0ac89e813f94042292aa1e77c73773c85cf881a9343b3f50711f13fa17"
                    "b50f4e5cb04ac5f6fc3106a6ef4c9732016c4e08e301eefac191994591"
                    "29a41a7589e0628";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "65a0b97048067a0c9040acbb5d7f6e2e6ac462e1e0064a8ce5b5bbf"
                       "8e57059e25a3ef8c80fc9037ae08f63e63f5bdb9378c322ad9b2daf"
                       "839fad7a75b1027abb6f70f110247da7e971c7c52914e5a4f776185"
                       "4432fa16b2a521e7bcaee2c735a87cad20c535bf6d04a87340c229b"
                       "f9af8647eedca9e2dc0b5aa90f7fea3cdc0a";
    ecdsa_param.d = "0a43b32ad7327ec92c0a67279f417c8ada6f40d6282fe79d6dc23b8702"
                    "147a31162e646291e8df460d39d7cdbdd7b2e7c6c89509b7ed3071b68d"
                    "4a518ba48e63662";
    ecdsa_param.k = "0383eda042e06c0297fbd279a2ad40559c5c12ad458f73458eebcc92b3"
                    "08d3c4fcec20a5b59f698e16fa6ea02dba8661b6955f67c052f67b0a56"
                    "460869f24cfdf7d";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "d6e366a87808eea5d39fe77cac4b8c754e865a796062e2ec89f7216"
                       "5cd41fe04c48148068c570e0d29afe9011e7e7a2461f4d9897d8c1f"
                       "a14b4ff88cab40059d17ab724f4039244e97fcecb07f9ffeec2fb9d"
                       "6b1896700fe374104a8c44af01a10e93b268d25367bf2bef488b8ab"
                       "cc1ef0e14c3e6e1621b2d58753f21e28b86f";
    ecdsa_param.d = "03c08fdccb089faee91dac3f56f556654a153cebb32f238488d925afd4"
                    "c7027707118a372f2a2db132516e12ec25f1664953f123ac2ac8f12e0d"
                    "cbbb61ff40fb721";
    ecdsa_param.k = "0d0e90d5ee7b5036655ad5c8f6a112c4b21c9449ca91c5c78421e364a2"
                    "160bbac4428303657bc11ea69f59fb0fe85a41b8f155a362343094456f"
                    "d2a39f2a79e4804";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "f99e1d272d0f5fb9c4f986e873d070ec638422bc04b47c715595e2c"
                       "f1a701cdf88bc6c4b20085b357bad12ccba67cac8a5ca07f31ba432"
                       "f9154ff1fadefd487a83a9c37e49fb70a2f170e58889cab0552e0a3"
                       "806ccfa2a60d96e346851d84b7de6d1a4b8cf37567dc161a84f1342"
                       "1e3412457d4bc27f6213453c8519a2d7daa2";
    ecdsa_param.d = "0969b515f356f8bb605ee131e80e8831e340902f3c6257270f7dedb2ba"
                    "9d876a2ae55b4a17f5d9acd46c1b26366c7e4e4e90a0ee5cff69ed9b27"
                    "8e5b1156a435f7e";
    ecdsa_param.k = "19029260f88e19360b70c11107a92f06faa64524cfbd9f70fecf02bd5a"
                    "94f390582a7f4c92c5313bb91dc881596768d86f75a0d6f452094adbe1"
                    "1d6643d1a0b2135";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "91f1ca8ce6681f4e1f117b918ae787a888798a9df3afc9d0e922f51"
                       "cdd6e7f7e55da996f7e3615f1d41e4292479859a44fa18a5a006662"
                       "610f1aaa2884f843c2e73d441753e0ead51dffc366250616c706f07"
                       "128940dd6312ff3eda6f0e2b4e441b3d74c592b97d9cd910f979d7f"
                       "39767b379e7f36a7519f2a4a251ef5e8aae1";
    ecdsa_param.d = "013be0bf0cb060dbba02e90e43c6ba6022f201de35160192d33574a67f"
                    "3f79df969d3ae87850071aac346b5f386fc645ed1977bea2e8446e0c58"
                    "90784e369124418";
    ecdsa_param.k = "1a363a344996aac9a3ac040066a65856edfb36f10bb687d4821a2e0299"
                    "b329c6b60e3547dde03bdbd1afa98b0b75d79cf5aac0ef7a3116266cad"
                    "f3dfbd46f8a4bfc";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp521r1 && dgst_len == SHA384_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "dbc094402c5b559d53168c6f0c550d827499c6fb2186ae2db15b89b"
                       "4e6f46220386d6f01bebde91b6ceb3ec7b4696e2cbfd14894dd0b7d"
                       "656d23396ce920044f9ca514bf115cf98ecaa55b950a9e49365c2f3"
                       "a05be5020e93db92c37437513044973e792af814d0ffad2c8ecc89a"
                       "e4b35ccb19318f0b988a7d33ec5a4fe85dfe";
    ecdsa_param.d = "095976d387d814e68aeb09abecdbf4228db7232cd3229569ade537f33e"
                    "07ed0da0abdee84ab057c9a00049f45250e2719d1ecaccf91c0e6fcdd4"
                    "016b75bdd98a950";
    ecdsa_param.k = "0a8d90686bd1104627836afe698effe22c51aa3b651737a940f2b0f9cd"
                    "72c594575e550adb142e467a3f631f4429514df8296d8f5144df86faa9"
                    "e3a8f13939ad5b3";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "114187efd1f6d6c46473fed0c1922987c79be2144439c6f61183caf"
                       "2045bfb419f8cddc82267d14540624975f27232117729ccfeacccc7"
                       "ecd5b71473c69d128152931865a60e6a104b67afe5ed443bdbcdc45"
                       "372f1a85012bbc4614d4c0c534aacd9ab78664dda9b1f1e255878e8"
                       "ac59e23c56a686f567e4b15c66f0e7c0931e";
    ecdsa_param.d = "04ceb9896da32f2df630580de979515d698fbf1dd96bea889b98fc0efd"
                    "0751ed35e6bcf75bc5d99172b0960ffd3d8b683fbffd4174b379fbdecd"
                    "7b138bb9025574b";
    ecdsa_param.k = "046639c5a3ec15afae5e4a7a418ac760846512d880c359bc2c751b199c"
                    "e43b10887e861b14127809754dbea47f6cc0140d2817e3f5b9a80ce01a"
                    "bd81f81b748433a";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "6744b69fc2420fe00f2352399bd58719e4ecdd6d602e2c80f194d60"
                       "7e58b27a0854745bfd6d504de2eb30b04cee0f44af710dd77e2f816"
                       "ac3ac5692fad2d1d417893bb0edba2707a4c146a486f8728ca696d3"
                       "5cc52e9c7187c82d4bdb92eb954794e5ad15133f6bfea1f025da32a"
                       "da710a3014cf11095b3ff69a94d087f17753";
    ecdsa_param.d = "00a8db566bd771a9689ea5188c63d586b9c8b576dbe74c06d618576f61"
                    "365e90b843d00347fdd084fec4ba229fe671ccdd5d9a3afee821a84af9"
                    "560cd455ed72e8f";
    ecdsa_param.k = "1e7b5e53571a24bd102dd7ad44a4b8d8a4e60e5957bc3c4e5d3c73109f"
                    "55233f072e572c7892f425ba5e64d3cb7966096bb34a47e26cd5b3e3b4"
                    "4108b310d9f681b";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "16001f4dcf9e76aa134b12b867f252735144e523e40fba9b4811b07"
                       "448a24ef4ccf3e81fe9d7f8097ae1d216a51b6eefc83880885e5b14"
                       "a5eeee025c4232319c4b8bce26807d1b386ad6a964deb3bdca30ee1"
                       "96cfdd717facfad5c77d9b1d05fdd96875e9675e85029ecbf4f94c5"
                       "24624746b7c42870c14a9a1454acf3354474";
    ecdsa_param.d = "1a300b8bf028449344d0e736145d9dd7c4075a783cb749e1ec7988d604"
                    "40a07021a25a3de74ea5e3d7bd4ab774d8ad6163adae31877ef0b2bd50"
                    "e26e9e4be8a7b66";
    ecdsa_param.k = "05a2e92717bb4dab3ee76724d4d9c2d58a32b873e491e36127985f0c99"
                    "60c610962ca1c4510dba75c98d83beebdc58b1d8678e054640951d11db"
                    "1bd2d8a4ab8476b";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "a9824a7b810aa16690083a00d422842971baf400c3563baa789c565"
                       "3fc13416111c0236c67c68e95a13cec0df50324dcc9ae780ce42326"
                       "07cb57dd9b2c61b382f0fa51fd4e283e2c55ffe272597651659fbd8"
                       "8cd03bfa9652cd54b01a7034c83a602709879e1325c77969bebfd93"
                       "932ce09a23eae607374602201614ff84b141";
    ecdsa_param.d = "06a253acd79912a74270fc0703ed6507ab20a970f2bc2277f782062092"
                    "cf0e60ae1ca1bb44dec003169bc25ef6e7123dd04692f77b181a6d7e69"
                    "2e66b09d35a540c";
    ecdsa_param.k = "165faf3727e42fd61345cfa7b93e55fb4bf583b24bdc14ce635b6c99db"
                    "d788012f14da9a210b677c44acdd851e672f1a48188d6b8946c0efeebf"
                    "e8a597ba0090a2c";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "90d8bbf714fd2120d2144022bf29520842d9fbd2dc8bb734b3e892b"
                       "a0285c6a342d6e1e37cc11a62083566e45b039cc65506d20a7d8b51"
                       "d763d25f0d9eaf3d38601af612c5798a8a2c712d968592b6ed689b8"
                       "8bbab95259ad34da26af9dda80f2f8a02960370bdb7e7595c0a4fff"
                       "b465d7ad0c4665b5ec0e7d50c6a8238c7f53";
    ecdsa_param.d = "0d5a5d3ddfd2170f9d2653b91967efc8a5157f8720d740dd974e272aab"
                    "000cc1a4e6c630348754ab923cafb5056fc584b3706628051c557fce67"
                    "744ee58ba7a56d0";
    ecdsa_param.k = "03269983a5c2bcc98e9476f5abf82424566b1f08b17204d29e310ece88"
                    "f99eb677a537f86fe2529e409cfef2c12929644100099e0de2f27c0f0a"
                    "c11105a4dca935b";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "09952b1e09995e95bf0022e911c6ab1a463b0a1fdd0eec69117b34a"
                       "f1103c720b57600217de7cd178fef92de5391e550af72a8dcf7badf"
                       "25b06dd039417f9a7d0f5be88fcd4e9655931d5b605452a667c9d1b"
                       "ae91d3476e7d51cff4108f116a49966fb3a7cff8df1c09734ce5620"
                       "faf2dccb3dc5d94e7e9ac812da31f6d07a38";
    ecdsa_param.d = "1bcedf920fa148361671b43c64e3186e1937eb1bd4b28cbd84c4214723"
                    "94552889bc05509aa732ef69d732b21b750523fdfd811f36467690fe94"
                    "e01e64c9d5cbbe9";
    ecdsa_param.k = "046e619b83aac868b26d0b3cbfab55e630e0b55c461985b5d00f94ff3a"
                    "5ce90ff412cebf46bbd84550d2031d573ca27d924624428360708c8d84"
                    "91c29eb01d30f2e";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "0bb0f80cff309c65ff7729c59c517d50fc0ed5be405ef70cb910c3f"
                       "62c328c90853d4473530b654dda6156e149bc2222a8a7f9be665240"
                       "e2fbe9d03f78a2356af0bacd1edb84c4801adc8293a8a0bd6123d1c"
                       "f6ba216aca807a7eb4dca76b493eb6e3dbb69d36f0f00f856222f24"
                       "d9b93ec34c3b261be2fca0451c00571928e5";
    ecdsa_param.d = "03789e04b3a2a0254ade3380172c150d2fad033885e02ea8bea5b92db3"
                    "f4adbab190ae423080a1154dfedec694c25eab46ce638be3db4e4cba67"
                    "bc39f62d6e7db2d";
    ecdsa_param.k = "0fbccd8d7804bdd1d1d721b5ec74d4ba37603bc306f9fce2ec241853d8"
                    "e07334e6b4b12c4ecca0c54bd71193dd7146507933a20737c5f3e15085"
                    "830fab9b30ca57b";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "7efacf213382ce30804e78b7256854d759147dba9729c51b2759465"
                       "715bf2c421034c23dc651c13d6cce95f71fe6a84dfbee5768163ac5"
                       "789ac0474c5ddf4115684683c5f7c204b33b8bcc0c03ac58f66cef2"
                       "f53b721fe2fac91ad841126101a88f512a7c2ded38549d9f050d4b7"
                       "961dda48a1489f026c5d111701762418cfe3";
    ecdsa_param.d = "124700aa9186353e298edefc57bec0c7d0201cca10c1d80dd408d5d710"
                    "40592b0ac59facdadfa8712445f5977ef8d4854022720c3f02d60e0732"
                    "dbb2f171fcf1490";
    ecdsa_param.k = "01a05238d595ded5c61d3bf6fde257dbf13095af8a5cb3a2e579e8e4c5"
                    "50fe31d12b71cc2dbcb295e6c4fd0fb8c22d1b741c097cc59d826ced1a"
                    "8771f09983143c4";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "28edff8b9d85f5f58499cc11f492abdfab25e8945975bbaeee910af"
                       "a2b8fc1295ec61406309ce4e09f4ab4f462959fc2a2786802466eb2"
                       "6d3b01be6919893ae75d0fdc2dc8a82e662550f9fce9627dd364188"
                       "aaba5c6faa1b2d8a2235adfa5ad0dc140f88a2b2f103f5690e877d0"
                       "7fe8fd30d02d2b2729bd3d8eb5b23a21f54c";
    ecdsa_param.d = "1f532d01af885cb4ad5c329ca5d421c5c021883bd5404c798d617679bb"
                    "8b094cbb7e15c832fb436325c5302313ce5e496f9513455e7021ffad75"
                    "777a19b226acfa1";
    ecdsa_param.k = "14e66853e0f7cd3300ebcae06048532e19cbb95bee140edc1c867ce731"
                    "0637651445b6dfeb1d99d2e32f2ffb787ebe3fe35032277f185d3dad84"
                    "f95806924550abe";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "bae2a8897c742fd99fbf813351cd009d3f2e18d825ca22e11527648"
                       "4bce8f82f8c7c0c21dd2af208404d8ef45bb5a6c41693912b630897"
                       "d5246801bf0775aa9bbac8be98cb861d172c3563dc59e78a58ed13c"
                       "66dea496471b3ad0eeae8995293e4ab97373edc1837ffc95ff1cc0c"
                       "1e90e64ea8680b2ca5f1e09bf86b99b343b6";
    ecdsa_param.d = "11abf508bca68a85a54bc0659e77efad3c86112c9db04db2883e76144a"
                    "a446918bb4bb0784b0b6a0e9aa47399fe3de5aaecfd8894a0d130bb0c3"
                    "66c40d9d5050745";
    ecdsa_param.k = "19cadb8c7eb10565aa4567e0709873918720f0e4b42b4817afb0b0547c"
                    "70cd1100229deae97a276b9c98ea58b01d4839fee86336d749d123b03e"
                    "8b1a31166acc110";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "d57a26a9593e72bfc87322524639bcaae5f2252d18b99cdaa03b144"
                       "45b0b8a4dd53928f66a2e4f202fb25b19cad0eb2f1bfda2ab9b0eb6"
                       "68cdcd0fe72f5d9ef2e45e0218590f7ab9d2c9342202610c698bc78"
                       "6cce108a7d4a6730a13e9ea1b470e781f1237d3f84f44abde808516"
                       "975546bd89075ef9a9732bfd7ee33b6f4399";
    ecdsa_param.d = "18dbf520d58177e4b7a0627674d220137983f486dd2fd3639f19751804"
                    "e80df0655db6afd829cdf75238de525e1a7a9f048049b593dd64b4b96c"
                    "c013f970c05ea1f";
    ecdsa_param.k = "098faeb73054639cb2e4442cd68e7b3a13f4b3f397a7b26f303afa4078"
                    "9f8ddd3d918f1ce4f0be53c8cb69c380744e2297d7fc01e2b3daef4ce6"
                    "4dd3a2644234753";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "8fdcf5084b12cfc043dd3416b46274e021bbed95d341d3c500c102a"
                       "5609d3a34de29f8fa9f0adb611a1f47a97ad981f8129d718fc0d6c7"
                       "09eab1a3490db8d550f34eb905b9e00663543afc5bc155e368e0bc9"
                       "19a8b8c9fa42093603537a5614927efa6be819ed42ececbf1a80a61"
                       "e6e0a7f9b5bc43b9238e62d5df0571fea152";
    ecdsa_param.d = "002764f5696aa813cd55d30948585f86288ae05aeb264ca157cd09e1d0"
                    "9a10515a849b0791b755ccc656a34707be9e52f5762d290a7d2bcd6de5"
                    "2c600ff862eaf4e";
    ecdsa_param.k = "08bffb0778cbb06466cecc114b9e89ca243a2b2b5e2597db920bc73a8b"
                    "bcbe3f57144ad33409ef7faaab430e13f4c42d304d11347360c84972ca"
                    "20b1539cce3a288";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "00669f433934992257bed55861df679804107d7fa491672574a7624"
                       "949c60049b0533383c88d6896c8de860704c3e6a6aefce83efa57c4"
                       "d57e9ab253da5d15e1f53ab6dce218b592772ab0bc01fee8e63368e"
                       "85c0639301456fe2d44cd5396a7f2b22761cd03b80eba7883eede82"
                       "49a2f5db2183bf00550c5c002f45a5e4fb31";
    ecdsa_param.d = "1b0c9acd3eeb618b4b0de4db402206f0f29adc69d7ad324b6db6601b35"
                    "1f723ac8fe949eeacd34228649bf0126276e5aceb0137d00c30dd858ae"
                    "f2d6b6449de2e89";
    ecdsa_param.k = "1fdc4f108070af3c66c9ba7b6c1f2603a19ceb4760399df81228cfc7ea"
                    "fde1082b5a0716a3ff82fbe84726f14dd0db3376ca184a78c3c60679ba"
                    "b6cd45f77f9b9ce";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "4be81dcfab39a64d6f00c0d7fff94dabdf3473dc49f0e12900df328"
                       "d6584b854fbaebaf3194c433e9e21743342e2dd056b445c8aa7d30a"
                       "38504b366a8fa889dc8ecec35b3130070787e7bf0f22fab5bea54a0"
                       "7d3a75368605397ba74dbf2923ef20c37a0d9c64caebcc93157456b"
                       "57b98d4becb13fecb7cc7f3740a6057af287";
    ecdsa_param.d = "181e1037bbec7ca2f271343e5f6e9125162c8a8a46ae8baa7ca7296602"
                    "ae9d56c994b3b94d359f2b3b3a01deb7a123f07d9e0c2e729d37cc5abd"
                    "ec0f5281931308a";
    ecdsa_param.k = "09078beaba465ba7a8b3624e644ac1e97c654533a58ac755e90bd606e2"
                    "214f11a48cb51f9007865a0f569d967ea0370801421846a89f3d09eb0a"
                    "481289270919f14";
    array[14] = ecdsa_param;
    return;
  }
  if (group == secp521r1 && dgst_len == SHA512_DIGEST_LENGTH)
  {
    ecdsa_param.dgst_len = dgst_len;
    ecdsa_param.dgst = "9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4"
                       "c1088fab1964ecb7904dc6856865d6c8e15041ccf2d5ac302e99d34"
                       "6ff2f686531d25521678d4fd3f76bbf2c893d246cb4d7693792fe18"
                       "172108146853103a51f824acc621cb7311d2463c3361ea707254f2b"
                       "052bc22cb8012873dcbb95bf1a5cc53ab89f";
    ecdsa_param.d = "0f749d32704bc533ca82cef0acf103d8f4fba67f08d2678e515ed7db88"
                    "6267ffaf02fab0080dca2359b72f574ccc29a0f218c8655c0cccf9fee6"
                    "c5e567aa14cb926";
    ecdsa_param.k = "03af5ab6caa29a6de86a5bab9aa83c3b16a17ffcd52b5c60c769be3053"
                    "cdddeac60812d12fecf46cfe1f3db9ac9dcf881fcec3f0aa733d4ecbb8"
                    "3c7593e864c6df1";
    array[0] = ecdsa_param;
    ecdsa_param.dgst = "b3c63e5f5a21c4bfe3dbc644354d9a949186d6a9e1dd873828782aa"
                       "6a0f1df2f64114a430b1c13fe8a2e09099e1ed05ef70de698161039"
                       "ded73bcb50b312673bb073f8a792ac140a78a8b7f3586dffb1fc8be"
                       "4f54516d57418ccc9945025ce3acf1eb84f69ceee5e9bd10c18c251"
                       "dbc481562cd3aae54b54ab618cb1eeda33cf";
    ecdsa_param.d = "1a4d2623a7d59c55f408331ba8d1523b94d6bf8ac83375ceb57a2b395a"
                    "5bcf977cfc16234d4a97d6f6ee25a99aa5bff15ff535891bcb7ae849a5"
                    "83e01ac49e0e9b6";
    ecdsa_param.k = "0bc2c0f37155859303de6fa539a39714e195c37c6ea826e224c8218584"
                    "ae09cd0d1cc14d94d93f2d83c96e4ef68517fdb3f383da5404e5a426bf"
                    "c5d424e253c181b";
    array[1] = ecdsa_param;
    ecdsa_param.dgst = "6e0f96d56505ffd2d005d5677dbf926345f0ff0a5da456bbcbcfdc2"
                       "d33c8d878b0bc8511401c73168d161c23a88b04d7a9629a7a6fbcff"
                       "241071b0d212248fcc2c94fa5c086909adb8f4b9772b4293b4acf52"
                       "15ea2fc72f8cec57b5a13792d7859b6d40348fc3ba3f5e7062a1907"
                       "5a9edb713ddcd391aefc90f46bbd81e2557b";
    ecdsa_param.d = "14787f95fb1057a2f3867b8407e54abb91740c097dac5024be92d5d656"
                    "66bb16e4879f3d3904d6eab269cf5e7b632ab3c5f342108d1d4230c301"
                    "65fba3a1bf1c66f";
    ecdsa_param.k = "186cd803e6e0c9925022e41cb68671adba3ead5548c2b1cd09348ab196"
                    "12b7af3820fd14da5fe1d7b550ed1a3c8d2f30592cd7745a3c09ee7b5d"
                    "cfa9ed31bdd0f1f";
    array[2] = ecdsa_param;
    ecdsa_param.dgst = "3f12ab17af3c3680aad22196337cedb0a9dba22387a7c555b46e841"
                       "76a6f8418004552386ada4deec59fdabb0d25e1c6668a96f100b352"
                       "f8dabd24b2262bd2a3d0f825602d54150bdc4bcbd5b8e0ca52bc8d2"
                       "c70ff2af9b03e20730d6bd9ec1d091a3e5c877259bcff4fd2c17a12"
                       "bfc4b08117ec39fe4762be128d0883a37e9d";
    ecdsa_param.d = "15807c101099c8d1d3f24b212af2c0ce525432d7779262eed0709275de"
                    "9a1d8a8eeeadf2f909cf08b4720815bc1205a23ad1f825618cb78bde74"
                    "7acad8049ca9742";
    ecdsa_param.k = "096731f8c52e72ffcc095dd2ee4eec3da13c628f570dba169b4a7460ab"
                    "471149abdede0b63e4f96faf57eab809c7d2f203fd5ab406c7bd79869b"
                    "7fae9c62f97c794";
    array[3] = ecdsa_param;
    ecdsa_param.dgst = "a1eed24b3b7c33296c2491d6ee092ec6124f85cf566bb5bc35bffb5"
                       "c734e34547242e57593e962fb76aee9e800eed2d702cc301499060b"
                       "76406b347f3d1c86456978950737703c8159001e6778f69c734a56e"
                       "5ce5938bd0e0de0877d55adeee48b0d8dfa4ac65fd2d3ce3e12878b"
                       "ac5c7014f9284d161b2a3e7d5c88569a45f6";
    ecdsa_param.d = "18692def0b516edcdd362f42669999cf27a65482f9358fcab312c6869e"
                    "22ac469b82ca9036fe123935b8b9ed064acb347227a6e377fb156ec833"
                    "dab9f170c2ac697";
    ecdsa_param.k = "161cf5d37953e09e12dc0091dc35d5fb3754c5c874e474d2b4a4f1a90b"
                    "870dff6d99fb156498516e25b9a6a0763170702bb8507fdba4a6131c72"
                    "58f6ffc3add81fd";
    array[4] = ecdsa_param;
    ecdsa_param.dgst = "9aace26837695e6596007a54e4bccdd5ffb16dc6844140e2eeeb584"
                       "b15acb2bbffd203c74440b6ee8db676fd200b4186a8c3e957c19e74"
                       "d4d865ada83f80655323dfa3570907ed3ce853b6e8cc375ed2d758a"
                       "2f5ad265dd3b47650517a49b3d02df9e0c60c21576378c2b3a08481"
                       "eec129b2a75608e13e6420127a3a63c8a3f1";
    ecdsa_param.d = "0a63f9cdefbccdd0d5c9630b309027fa139c31e39ca26686d76c22d409"
                    "3a2a5e5ec4e2308ce43eb8e563187b5bd811cc6b626eace4063047ac04"
                    "20c3fdcff5bdc04";
    ecdsa_param.k = "01e51fd877dbbcd2ab138fd215d508879298d10c7fcbdcc91880240708"
                    "8eb6ca0f18976a13f2c0a57867b0298512fc85515b209c4435e9ef30ab"
                    "01ba649838bc7a0";
    array[5] = ecdsa_param;
    ecdsa_param.dgst = "ac2175940545d4fbab6e2e651c6830aba562e0c11c919e797c43eff"
                       "9f187a68a9e5a128e3e2a330b955a3f4577d3f826529ad1b03d7b60"
                       "f7ad678f005053b41dc0f8d267f3685c6abe1a0e9a733c44b2f3ca4"
                       "8b90806f935141c842e3a6c06a58f5343d75e3585971a734f4ae107"
                       "4ce5b54f74bd9342f4bbca738d260393f43e";
    ecdsa_param.d = "024f7d67dfc0d43a26cc7c19cb511d30a097a1e27e5efe29e9e76e4384"
                    "9af170fd9ad57d5b22b1c8840b59ebf562371871e12d2c1baefc1abaed"
                    "c872ed5d2666ad6";
    ecdsa_param.k = "1c1308f31716d85294b3b5f1dc87d616093b7654907f55289499b419f3"
                    "8ceeb906d2c9fe4cc3d80c5a38c53f9739311b0b198111fede72ebde3b"
                    "0d2bc4c2ef090d2";
    array[6] = ecdsa_param;
    ecdsa_param.dgst = "6266f09710e2434cb3da3b15396556765db2ddcd221dce257eab739"
                       "9c7c490135925112932716af1434053b8b9fe340563e57a0b9776f9"
                       "ac92cbb5fba18b05c0a2fafbed7240b3f93cd1780c980ff5fe92610"
                       "e36c0177cabe82367c84cee9020cf26c1d74ae3eb9b9b512cb8b3cb"
                       "3d81b17cf20dc76591b2b394ef1c62ac12ee";
    ecdsa_param.d = "0349471460c205d836aa37dcd6c7322809e4e8ef81501e5da87284b267"
                    "d843897746b33016f50a7b702964910361ed51d0afd9d8559a47f0b7c2"
                    "5b2bc952ce8ed9e";
    ecdsa_param.k = "00eb2bd8bb56b9d2e97c51247baf734cc655c39e0bfda35375f0ac2fe8"
                    "2fad699bf1989577e24afb33c3868f91111e24fefe7dec802f3323ac01"
                    "3bec6c048fe5568";
    array[7] = ecdsa_param;
    ecdsa_param.dgst = "3de9e617a6868dca1a1432d503f923535da3f9b34426b2a48221743"
                       "99c73b1c1ee67311410a58c17202ac767844b2024d8aa21a205707d"
                       "93865693ac25a24fc87034fa3a7a7e27c3344cb03b87602c15180a5"
                       "fe6a9dd90cd11af4a0f150207bf2d83f55b12c088adae99aa8cfa65"
                       "9311b3a25beb99056643760d6a282126b9b2";
    ecdsa_param.d = "07788d34758b20efc330c67483be3999d1d1a16fd0da81ed28895ebb35"
                    "ee21093d37ea1ac808946c275c44454a216195eb3eb3aea1b53a329eca"
                    "4eb82dd48c784f5";
    ecdsa_param.k = "0a73477264a9cc69d359464abb1ac098a18c0fb3ea35e4f2e6e1b060da"
                    "b05bef1255d9f9c9b9fbb89712e5afe13745ae6fd5917a9aedb0f2860d"
                    "03a0d8f113ea10c";
    array[8] = ecdsa_param;
    ecdsa_param.dgst = "aa48851af7ef17abe233163b7185130f4646203c205e22bcc2a5a36"
                       "97bcab998c73a9ffe1d3ea0b7978ce7df937a72586eb5ca60b0d939"
                       "a7d1c115c820171c89c8116b7e2c7b98cf0f14e4c4df3cb2f319ad3"
                       "ab0ea25ff14526ddc037469f000bf82100acd4cdf94feb4eba4ea17"
                       "26f0569336604a473aee67d71afebb569209";
    ecdsa_param.d = "1f98696772221e6cccd5569ed8aed3c435ee86a04689c7a64d20c30f6f"
                    "e1c59cc10c6d2910261d30c3b96117a669e19cfe5b696b68feeacf61f6"
                    "a3dea55e6e5837a";
    ecdsa_param.k = "1a277cf0414c6adb621d1cc0311ec908401ce040c6687ed45a0cdf2910"
                    "c42c9f1954a4572d8e659733d5e26cbd35e3260be40017b2f5d38ec423"
                    "15f5c0b056c596d";
    array[9] = ecdsa_param;
    ecdsa_param.dgst = "b0d5d52259af364eb2d1a5027e5f7d0afe4b999cc5dd2268cfe76f5"
                       "1d2f17b541bdd7867e23a1bb897705153d9432a24012108979c6a2c"
                       "9e2567c9531d012f9e4be764419491a52eae2e127430b0ab58cb8e2"
                       "16515a821b3db206447c235bf44ee304201b483b2a88844abaa18bc"
                       "a0147dfff7e502397dd62e15524f67eb2df2";
    ecdsa_param.d = "13c3852a6bc8825b45fd7da1754078913d77f4e586216a6eb08b6f03ad"
                    "ce7464f5dbc2bea0eb7b12d103870ef045f53d67e3600d7eba07aac5db"
                    "03f71b64db1cceb";
    ecdsa_param.k = "1e25b86db041f21c2503d547e2b1b655f0b99d5b6c0e1cf2bdbd8a8c6a"
                    "053f5d79d78c55b4ef75bff764a74edc920b35536e3c470b6f6b8fd538"
                    "98f3bbc467539ef";
    array[10] = ecdsa_param;
    ecdsa_param.dgst = "9599788344976779383a7a0812a096943a1f771ee484d586af1a062"
                       "07478e4c0be9c200d42460fe837e24b266c8852d80d3c53cc52ffb1"
                       "913fc3261145fc6da575611efd16c026059a2e64f802517ffd1b6b3"
                       "4de10ad2909c65c2155e8d939b8115400c1d793d23955b15f5d1c13"
                       "c962ff92b4a815cee0e10f8e14e1f6e6cd38";
    ecdsa_param.d = "1654eaa1f6eec7159ee2d36fb24d15d6d33a128f36c52e2437f7d1b5a4"
                    "4ea4fa965c0a26d0066f92c8b82bd136491e929686c8bde61b7c704daa"
                    "b54ed1e1bdf6b77";
    ecdsa_param.k = "1b7519becd00d750459d63a72f13318b6ac61b8c8e7077cf9415c9b4b9"
                    "24f35514c9c28a0fae43d06e31c670a873716156aa7bc744577d62476e"
                    "038b116576a9e53";
    array[11] = ecdsa_param;
    ecdsa_param.dgst = "fdde51acfd04eb0ad892ce9d6c0f90eb91ce765cbe3ce9d3f2defe8"
                       "f691324d26b968b8b90e77706b068585f2a3ee7bf3e910528f7403c"
                       "5af745a6f9d7ba6c53abd885c3b1be583415b128f4d3f224daf8563"
                       "476bd9aa61e9c8518c144335f8f879c03696bddbe3ac37a8fbede29"
                       "861611feaa87e325e2f60278b4893ed57fb0";
    ecdsa_param.d = "1cba5d561bf18656991eba9a1dde8bde547885ea1f0abe7f2837e569ca"
                    "52f53df5e64e4a547c4f26458b5d9626ed6d702e5ab1dd585cf36a0c84"
                    "f768fac946cfd4c";
    ecdsa_param.k = "0e790238796fee7b5885dc0784c7041a4cc7ca4ba757d9f7906ad1fcba"
                    "b5667e3734bc2309a48047442535ff89144b518f730ff55c0c67eeb4c8"
                    "80c2dfd2fb60d69";
    array[12] = ecdsa_param;
    ecdsa_param.dgst = "beb34c997f905c77451ac392f7957a0ab8b23325bd5c63ca31c109a"
                       "c8f655a1e3094240cb8a99284f8091de2ab9a7db2504d16251980b8"
                       "6be89ec3a3f41162698bab51848880633e0b71a38f8896335853d8e"
                       "836a2454ecab2acdcc052c8f659be1d703b13ae1b090334ac50ab01"
                       "37ddb5e8b924c0e3d2e5789daaef2fdd4a1e";
    ecdsa_param.d = "0972e7ff25adf8a032535e5b19463cfe306b90803bf27fabc6046ae080"
                    "7d2312fbab85d1da61b80b2d5d48f4e5886f27fca050b84563aee1926a"
                    "e6b2564cd756d63";
    ecdsa_param.k = "0517f6e4002479dc89e8cbb55b7c426d128776ca82cf81be8c1da95571"
                    "78783f40e3d047db7e77867f1af030a51de470ee3128c22e9c2d642d71"
                    "e4904ab5a76edfa";
    array[13] = ecdsa_param;
    ecdsa_param.dgst = "543c374af90c34f50ee195006d5f9d8dd986d09ad182fcbefa08556"
                       "7275eee1e742bfe0af3d058675adeb5b9f87f248b00a9fbd2aa7791"
                       "29123a5b983f2f26fc3caf2ea34277550c22fe8c814c739b46972d5"
                       "0232993cddd63a3c99e20f5c5067d9b57e2d5db94317a5a16b5c12b"
                       "5c4cafbc79cbc2f9940f074bbc7d0dc71e90";
    ecdsa_param.d = "1f0ec8da29295394f2f072672db014861be33bfd9f91349dad5566ff39"
                    "6bea055e53b1d61c8c4e5c9f6e129ed75a49f91cce1d5530ad4e78c2b7"
                    "93a63195eb9f0da";
    ecdsa_param.k = "0ac3b6d61ebda99e23301fa198d686a13c0832af594b289c9a55669ce6"
                    "d62011384769013748b68465527a597ed6858a06a99d50493562b3a7db"
                    "cee975ad34657d8";
    array[14] = ecdsa_param;
    return;
  }
}
