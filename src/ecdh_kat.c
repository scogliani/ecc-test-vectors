#include <openssl/bn.h>
#include <openssl/ecdh.h>

#include <ecc.h>
#include <ecdh_kat.h>
#include <utils.h>
#include <mk_eckey.h>

/**
 * Creates an elliptic curve cryptography (y^2 = x^3 + ax + b (mod p))
 * @param kcp prime modulus p of the field GF(p)
 * @param kca a value of the equation
 * @return
 */
static char *pt(unsigned char *md, size_t size);

char *ecdh_kat(EC_GROUP const *group, const char *priv, const char *kcx0,
               const char *kcy0)
{
  EC_KEY *key = NULL;
  size_t Ztmplen;
  unsigned char *Ztmp = NULL;
  char *p;

  if (!(key = mk_eckey(group, priv, kcx0, kcy0)))
    ABORT;

  Ztmplen = (size_t)(EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8;

  Ztmp = OPENSSL_malloc(Ztmplen);

  if (!ECDH_compute_key(Ztmp, Ztmplen, EC_KEY_get0_public_key(key), key, 0))
    ABORT;

  p = pt(Ztmp, Ztmplen);

  OPENSSL_free(Ztmp);
  EC_KEY_free(key);

  return p;
}

char *pt(unsigned char *md, size_t size)
{
  size_t i;
  char *buf = (char *)calloc(size * 4, sizeof(char));

  for (i = 0; i < size; i++)
    sprintf(&(buf[i * 2]), "%02x", md[i]);

  return (buf);
}

void ecdh_parameters_set_values(EC_GROUP const *group,
                                Ecdh_parameters array[ECDH_KAT_TEST_VECTOR])
{
  Ecdh_parameters ecdh_param;

  if (group == secp192r1)
  {
    ecdh_param.priv = "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527";
    ecdh_param.kcx0 = "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0";
    ecdh_param.kcy0 = "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523";
    array[0] = ecdh_param;
    ecdh_param.priv = "56e853349d96fe4c442448dacb7cf92bb7a95dcf574a9bd5";
    ecdh_param.kcx0 = "deb5712fa027ac8d2f22c455ccb73a91e17b6512b5e030e7";
    ecdh_param.kcy0 = "7e2690a02cc9b28708431a29fb54b87b1f0c14e011ac2125";
    array[1] = ecdh_param;
    ecdh_param.priv = "c6ef61fe12e80bf56f2d3f7d0bb757394519906d55500949";
    ecdh_param.kcx0 = "4edaa8efc5a0f40f843663ec5815e7762dddc008e663c20f";
    ecdh_param.kcy0 = "0a9f8dc67a3e60ef6d64b522185d03df1fc0adfd42478279";
    array[2] = ecdh_param;
    ecdh_param.priv = "e6747b9c23ba7044f38ff7e62c35e4038920f5a0163d3cda";
    ecdh_param.kcx0 = "8887c276edeed3e9e866b46d58d895c73fbd80b63e382e88";
    ecdh_param.kcy0 = "04c5097ba6645e16206cfb70f7052655947dd44a17f1f9d5";
    array[3] = ecdh_param;
    ecdh_param.priv = "beabedd0154a1afcfc85d52181c10f5eb47adc51f655047d";
    ecdh_param.kcx0 = "0d045f30254adc1fcefa8a5b1f31bf4e739dd327cd18d594";
    ecdh_param.kcy0 = "542c314e41427c08278a08ce8d7305f3b5b849c72d8aff73";
    array[4] = ecdh_param;
    ecdh_param.priv = "cf70354226667321d6e2baf40999e2fd74c7a0f793fa8699";
    ecdh_param.kcx0 = "fb35ca20d2e96665c51b98e8f6eb3d79113508d8bccd4516";
    ecdh_param.kcy0 = "368eec0d5bfb847721df6aaff0e5d48c444f74bf9cd8a5a7";
    array[5] = ecdh_param;
    ecdh_param.priv = "fe942515237fffdd7b4eb5c64909eee4856a076cdf12bae2";
    ecdh_param.kcx0 = "824752960c1307e5f13a83da21c7998ca8b5b00b9549f6d0";
    ecdh_param.kcy0 = "bc52d91e234363bc32ee0b6778f25cd8c1847510f4348b94";
    array[6] = ecdh_param;
    ecdh_param.priv = "33fed10492afa5bea0333c0af12cac940c4d222455bcd0fe";
    ecdh_param.kcx0 = "10bb57020291141981f833b4749e5611034b308e84011d21";
    ecdh_param.kcy0 = "e1cacd6b7bd17ed8ddb50b6aee0654c35f2d0eddc1cffcf6";
    array[7] = ecdh_param;
    ecdh_param.priv = "f3557c5d70b4c7954960c33568776adbe8e43619abe26b13";
    ecdh_param.kcx0 = "5192fce4185a7758ea1bc56e0e4f4e8b2dce32348d0dced1";
    ecdh_param.kcy0 = "20989981beaaf0006d88a96e7971a2fa3a33ba46047fc7ba";
    array[8] = ecdh_param;
    ecdh_param.priv = "586cfba1c6e81766ed52828f177b1be14ebbc5b83348c311";
    ecdh_param.kcx0 = "26d019dbe279ead01eed143a91601ada26e2f42225b1c62b";
    ecdh_param.kcy0 = "6ca653f08272e0386fc9421fbd580093d7ae6301bca94476";
    array[9] = ecdh_param;
    ecdh_param.priv = "cad8100603a4f65be08d8fc8a1b7e884c5ff65deb3c96d99";
    ecdh_param.kcx0 = "539bc40fe20a0fb267888b647b03eaaf6ec20c02a1e1f8c8";
    ecdh_param.kcy0 = "69095e5bb7b4d44c3278a7ee6beca397c45246da9a34c8be";
    array[10] = ecdh_param;
    ecdh_param.priv = "1edd879cc5c79619cae6c73a691bd5a0395c0ef3b356fcd2";
    ecdh_param.kcx0 = "5d343ddb96318fb4794d10f6c573f99fee5d0d57b996250f";
    ecdh_param.kcy0 = "99fbdf9d97dd88ad410235dac36e5b92ce2824b8e587a82c";
    array[11] = ecdh_param;
    ecdh_param.priv = "460e452273fe1827602187ad3bebee65cb84423bb4f47537";
    ecdh_param.kcx0 = "8d3db9bdce137ffbfb891388c37df6c0cbc90aa5e5376220";
    ecdh_param.kcy0 = "135d30b5cb660eef8764ffc744f15c1b5d6dc06ba4416d37";
    array[12] = ecdh_param;
    ecdh_param.priv = "b970365008456f8758ecc5a3b33cf3ae6a8d568107a52167";
    ecdh_param.kcx0 = "9e0a6949519c7f5be68c0433c5fdf13064aa13fb29483dc3";
    ecdh_param.kcy0 = "e1c8ba63e1f471db23185f50d9c871edea21255b3a63b4b7";
    array[13] = ecdh_param;
    ecdh_param.priv = "59c15b8a2464e41dfe4371c7f7dadf470ae425544f8113bd";
    ecdh_param.kcx0 = "be088238902e9939b3d054eeeb8492daf4bdcf09a2ab77f1";
    ecdh_param.kcy0 = "58d6749a3a923dc80440f2661fd35b651617e65294b46375";
    array[14] = ecdh_param;
    ecdh_param.priv = "a6e9b885c66b959d1fc2708d591b6d3228e49eb98f726d61";
    ecdh_param.kcx0 = "bf5ae05025e1be617e666d87a4168363873d5761b376b503";
    ecdh_param.kcy0 = "e1e6e38b372b6bee0ff5b3502d83735e3b2c26825e4f0fcc";
    array[15] = ecdh_param;
    ecdh_param.priv = "bdb754096ffbfbd8b0f3cb046ccb7ca149c4e7192067a3ee";
    ecdh_param.kcx0 = "6cc4feed84c7ab0d09005d660ed34de6955a9461c4138d11";
    ecdh_param.kcy0 = "31225f33864ed48da06fa45a913b46cf42557742e35085e6";
    array[16] = ecdh_param;
    ecdh_param.priv = "d5bcf2534dafc3d99964c7bd63ab7bd15999fe56dd969c42";
    ecdh_param.kcx0 = "36157315bee7afedded58c4e8ba14d3421c401e51135bcc9";
    ecdh_param.kcy0 = "37c297ca703f77c52bb062d8ce971db84097ba0c753a418f";
    array[17] = ecdh_param;
    ecdh_param.priv = "43d4b9df1053be5b4268104c02244d3bf9594b010b46a8b2";
    ecdh_param.kcx0 = "98464d47f0256f8292e027e8c92582ea77cf9051f5ce8e5d";
    ecdh_param.kcy0 = "449552ef7578be96236fe5ed9d0643c0bb6c5a9134b0108d";
    array[18] = ecdh_param;
    ecdh_param.priv = "94cac2c2ca714746401670d94edbf3f677867b5a03bee7ad";
    ecdh_param.kcx0 = "563eb66c334cf6f123bf04c7803b48a3110214237e983bf5";
    ecdh_param.kcy0 = "0f351104819199ef07c9a6051d20758f3af79027ea66a53f";
    array[19] = ecdh_param;
    ecdh_param.priv = "2a3a9e33c8cc3107a9f9265c3bdea1206570e86f92ac7014";
    ecdh_param.kcx0 = "86828c4ac92b5507618aec7873a1d4fc6543c5be33cf3078";
    ecdh_param.kcy0 = "b22ca72437545e10d6d4f052422eb898b737a4b8543ee550";
    array[20] = ecdh_param;
    ecdh_param.priv = "4a6b78a98ac98fa8e99a8ece08ec0251125f85c6fd0e289b";
    ecdh_param.kcx0 = "6700a102437781a9581da2bc25ced5abf419da91d3c803df";
    ecdh_param.kcy0 = "71396c9cf08bcd91854e3e6e42d8c657ce0f27ab77a9dc4b";
    array[21] = ecdh_param;
    ecdh_param.priv = "c5a6491d78844d6617ef33be6b8bd54da221450885d5950f";
    ecdh_param.kcx0 = "a82f354cf97bee5d22dc6c079f2902ead44d96a8f614f178";
    ecdh_param.kcy0 = "a654a9aa8a1a0802f2ce0ee8a0f4ebe96dee1b37464b1ff2";
    array[22] = ecdh_param;
    ecdh_param.priv = "2ba2703c5e23f6463c5b88dc37292fabd3399b5e1fb67c05";
    ecdh_param.kcx0 = "3cec21b28668a12a2cf78e1a8e55d0efe065152fffc34718";
    ecdh_param.kcy0 = "1029557beba4ff1992bd21c23cb4825f6dae70e3318fd1ca";
    array[23] = ecdh_param;
    ecdh_param.priv = "836118c6248f882e9147976f764826c1a28755a6102977d5";
    ecdh_param.kcx0 = "7082644715b8b731f8228b5118e7270d34d181f361a221fc";
    ecdh_param.kcy0 = "464649d6c88ca89614488a1cc7b8442bb42f9fb3020a3d76";
    array[24] = ecdh_param;
    return;
  }
  if (group == secp224r1)
  {
    ecdh_param.priv =
        "8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd";
    ecdh_param.kcx0 =
        "af33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280";
    ecdh_param.kcy0 =
        "882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7";
    array[0] = ecdh_param;
    ecdh_param.priv =
        "043cb216f4b72cdf7629d63720a54aee0c99eb32d74477dac0c2f73d";
    ecdh_param.kcx0 =
        "13bfcd4f8e9442393cab8fb46b9f0566c226b22b37076976f0617a46";
    ecdh_param.kcy0 =
        "eeb2427529b288c63c2f8963c1e473df2fca6caa90d52e2f8db56dd4";
    array[1] = ecdh_param;
    ecdh_param.priv =
        "5ad0dd6dbabb4f3c2ea5fe32e561b2ca55081486df2c7c15c9622b08";
    ecdh_param.kcx0 =
        "756dd806b9d9c34d899691ecb45b771af468ec004486a0fdd283411e";
    ecdh_param.kcy0 =
        "4d02c2ca617bb2c5d9613f25dd72413d229fd2901513aa29504eeefb";
    array[2] = ecdh_param;
    ecdh_param.priv =
        "0aa6ff55a5d820efcb4e7d10b845ea3c9f9bc5dff86106db85318e22";
    ecdh_param.kcx0 =
        "0f537bf1c1122c55656d25e8aa8417e0b44b1526ae0523144f9921c4";
    ecdh_param.kcy0 =
        "f79b26d30e491a773696cc2c79b4f0596bc5b9eebaf394d162fb8684";
    array[3] = ecdh_param;
    ecdh_param.priv =
        "efe6e6e25affaf54c98d002abbc6328da159405a1b752e32dc23950a";
    ecdh_param.kcx0 =
        "2b3631d2b06179b3174a100f7f57131eeea8947be0786c3dc64b2239";
    ecdh_param.kcy0 =
        "83de29ae3dad31adc0236c6de7f14561ca2ea083c5270c78a2e6cbc0";
    array[4] = ecdh_param;
    ecdh_param.priv =
        "61cb2932524001e5e9eeed6df7d9c8935ee3322029edd7aa8acbfd51";
    ecdh_param.kcx0 =
        "4511403de29059f69a475c5a6a5f6cabed5d9f014436a8cb70a02338";
    ecdh_param.kcy0 =
        "7d2d1b62aa046df9340f9c37a087a06b32cf7f08a223f992812a828b";
    array[5] = ecdh_param;
    ecdh_param.priv =
        "8c7ace347171f92def98d845475fc82e1d1496da81ee58f505b985fa";
    ecdh_param.kcx0 =
        "314a0b26dd31c248845d7cc17b61cad4608259bed85a58d1f1ffd378";
    ecdh_param.kcy0 =
        "66e4b350352e119eecada382907f3619fd748ea73ae4899dfd496302";
    array[6] = ecdh_param;
    ecdh_param.priv =
        "382feb9b9ba10f189d99e71a89cdfe44cb554cec13a212840977fb68";
    ecdh_param.kcx0 =
        "abe6843beec2fd9e5fb64730d0be4d165438ce922ed75dd80b4603e5";
    ecdh_param.kcy0 =
        "6afe8673a96c4ba9900ad85995e631e436c6cc88a2c2b47b7c4886b8";
    array[7] = ecdh_param;
    ecdh_param.priv =
        "e0d62035101ef487c485c60fb4500eebe6a32ec64dbe97dbe0232c46";
    ecdh_param.kcx0 =
        "13cf9d6d2c9aae8274c27d446afd0c888ffdd52ae299a35984d4f527";
    ecdh_param.kcy0 =
        "dcbee75b515751f8ee2ae355e8afd5de21c62a939a6507b538cbc4af";
    array[8] = ecdh_param;
    ecdh_param.priv =
        "b96ade5b73ba72aa8b6e4d74d7bf9c58e962ff78eb542287c7b44ba2";
    ecdh_param.kcx0 =
        "965b637c0dfbc0cf954035686d70f7ec30929e664e521dbaa2280659";
    ecdh_param.kcy0 =
        "82a58ff61bc90019bbcbb5875d3863db0bc2a1fa34b0ad4de1a83f99";
    array[9] = ecdh_param;
    ecdh_param.priv =
        "a40d7e12049c71e6522c7ff2384224061c3a457058b310557655b854";
    ecdh_param.kcx0 =
        "73cc645372ca2e71637cda943d8148f3382ab6dd0f2e1a49da94e134";
    ecdh_param.kcy0 =
        "df5c355c23e6e232ebc3bee2ab1873ee0d83e3382f8e6fe613f6343c";
    array[10] = ecdh_param;
    ecdh_param.priv =
        "ad2519bc724d484e02a69f05149bb047714bf0f5986fac2e222cd946";
    ecdh_param.kcx0 =
        "546578216250354e449e21546dd11cd1c5174236739acad9ce0f4512";
    ecdh_param.kcy0 =
        "d2a22fcd66d1abedc767668327c5cb9c599043276239cf3c8516af24";
    array[11] = ecdh_param;
    ecdh_param.priv =
        "3d312a9b9d8ed09140900bbac1e095527ebc9e3c6493bcf3666e3a29";
    ecdh_param.kcx0 =
        "1d46b1dc3a28123cb51346e67baec56404868678faf7d0e8b2afa22a";
    ecdh_param.kcy0 =
        "0ec9e65ec97e218373e7fc115c2274d5b829a60d93f71e01d58136c3";
    array[12] = ecdh_param;
    ecdh_param.priv =
        "8ce0822dc24c153995755ac350737ef506641c7d752b4f9300c612ed";
    ecdh_param.kcx0 =
        "266d038cc7a4fe21f6c976318e827b82bb5b8f7443a55298136506e0";
    ecdh_param.kcy0 =
        "df123d98a7a20bbdf3943df2e3563422f8c0cf74d53aaabdd7c973ba";
    array[13] = ecdh_param;
    ecdh_param.priv =
        "0ff9b485325ab77f29e7bc379fed74bfac859482da0dee7528c19db2";
    ecdh_param.kcx0 =
        "eb0a09f7a1c236a61f595809ec5670efd92e4598d5e613e092cdfdca";
    ecdh_param.kcy0 =
        "50787ae2f2f15b88bc10f7b5f0aee1418373f16153aebd1fba54288d";
    array[14] = ecdh_param;
    ecdh_param.priv =
        "19cf5ff6306467f28b9fe0675a43c0582552c8c12e59ce7c38f292b1";
    ecdh_param.kcx0 =
        "6b2f6b18a587f562ffc61bd9b0047322286986a78f1fd139b84f7c24";
    ecdh_param.kcy0 =
        "7096908e4615266be59a53cd655515056ff92370a6271a5d3823d704";
    array[15] = ecdh_param;
    ecdh_param.priv =
        "90a15368e3532c0b1e51e55d139447c2c89bc160719d697291ea7c14";
    ecdh_param.kcx0 =
        "328101ba826acd75ff9f34d5574ce0dbc92f709bad8d7a33c47940c1";
    ecdh_param.kcy0 =
        "df39f1ea88488c55d5538160878b9ced18a887ea261dd712d14024ff";
    array[16] = ecdh_param;
    ecdh_param.priv =
        "8e0838e05e1721491067e1cabc2e8051b290e2616eec427b7121897d";
    ecdh_param.kcx0 =
        "0081e34270871e2ebbd94183f617b4ae15f0416dd634fe6e934cf3c0";
    ecdh_param.kcy0 =
        "3a1e9f38a7b90b7317d26b9f6311063ab58b268cf489b2e50386d5d6";
    array[17] = ecdh_param;
    ecdh_param.priv =
        "38106e93f16a381adb1d72cee3da66ae462ad4bbfea9ecdf35d0814e";
    ecdh_param.kcx0 =
        "2623632fdf0bd856805a69aa186d4133ef5904e1f655a972d66cce07";
    ecdh_param.kcy0 =
        "2cef9728dd06fb8b50150f529b695076d4507983912585c89bd0682e";
    array[18] = ecdh_param;
    ecdh_param.priv =
        "e5d1718431cf50f6cbd1bc8019fa16762dfa12c989e5999977fb4ea2";
    ecdh_param.kcx0 =
        "8ee4d1dcc31dee4bf6fe21ca8a587721d910acfb122c16c2a77a8152";
    ecdh_param.kcy0 =
        "4ebf323fff04eb477069a0ac68b345f6b1ae134efc31940e513cb99f";
    array[19] = ecdh_param;
    ecdh_param.priv =
        "3d635691b62a9a927c633951c9369c8862bd2119d30970c2644727d6";
    ecdh_param.kcx0 =
        "97dcbe6d28335882a6d193cc54a1063dd0775dc328565300bb99e691";
    ecdh_param.kcy0 =
        "dad11dd5ece8cfd9f97c9a526e4a1506e6355969ee87826fc38bcd24";
    array[20] = ecdh_param;
    ecdh_param.priv =
        "acf3c85bbdc379f02f5ea36e7f0f53095a9e7046a28685a8659bf798";
    ecdh_param.kcx0 =
        "ce9126dd53972dea1de1d11efef900de34b661859c4648c5c0e534f7";
    ecdh_param.kcy0 =
        "e113b6f2c1659d07f2716e64a83c18bbce344dd2121fe85168eae085";
    array[21] = ecdh_param;
    ecdh_param.priv =
        "cffd62cb00a0e3163fbf2c397fadc9618210f86b4f54a675287305f0";
    ecdh_param.kcx0 =
        "84419967d6cfad41e75a02b6da605a97949a183a97c306c4b46e66a5";
    ecdh_param.kcy0 =
        "5cc9b259718b1bc8b144fde633a894616ffd59a3a6d5d8e942c7cbb7";
    array[22] = ecdh_param;
    ecdh_param.priv =
        "85f903e43943d13c68932e710e80de52cbc0b8f1a1418ea4da079299";
    ecdh_param.kcx0 =
        "7c9cac35768063c2827f60a7f51388f2a8f4b7f8cd736bd6bc337477";
    ecdh_param.kcy0 =
        "29ee6b849c6025d577dbcc55fbd17018f4edbc2ef105b004d6257bcd";
    array[23] = ecdh_param;
    ecdh_param.priv =
        "cce64891a3d0129fee0d4a96cfbe7ac470b85e967529057cfa31a1d9";
    ecdh_param.kcx0 =
        "085a7642ad8e59b1a3e8726a7547afbecffdac1dab7e57230c6a9df4";
    ecdh_param.kcy0 =
        "f91c36d881fe9b8047a3530713554a1af4c25c5a8e654dcdcf689f2e";
    array[24] = ecdh_param;
    return;
  }
  if (group == secp256r1 || group == frp256v1)
  {
    ecdh_param.priv =
        "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
    ecdh_param.kcx0 =
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    ecdh_param.kcy0 =
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    array[0] = ecdh_param;
    ecdh_param.priv =
        "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5";
    ecdh_param.kcx0 =
        "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae";
    ecdh_param.kcy0 =
        "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3";
    array[1] = ecdh_param;
    ecdh_param.priv =
        "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8";
    ecdh_param.kcx0 =
        "a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3";
    ecdh_param.kcy0 =
        "ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536";
    array[2] = ecdh_param;
    ecdh_param.priv =
        "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d";
    ecdh_param.kcx0 =
        "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed";
    ecdh_param.kcy0 =
        "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4";
    array[3] = ecdh_param;
    ecdh_param.priv =
        "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf";
    ecdh_param.kcx0 =
        "41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922";
    ecdh_param.kcy0 =
        "1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328";
    array[4] = ecdh_param;
    ecdh_param.priv =
        "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef";
    ecdh_param.kcx0 =
        "33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792";
    ecdh_param.kcy0 =
        "f2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f";
    array[5] = ecdh_param;
    ecdh_param.priv =
        "3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190";
    ecdh_param.kcx0 =
        "6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7";
    ecdh_param.kcy0 =
        "40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05";
    array[6] = ecdh_param;
    ecdh_param.priv =
        "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8";
    ecdh_param.kcx0 =
        "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb";
    ecdh_param.kcy0 =
        "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229";
    array[7] = ecdh_param;
    ecdh_param.priv =
        "0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d";
    ecdh_param.kcx0 =
        "94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9";
    ecdh_param.kcy0 =
        "d8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a";
    array[8] = ecdh_param;
    ecdh_param.priv =
        "2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08";
    ecdh_param.kcx0 =
        "e099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f";
    ecdh_param.kcy0 =
        "d9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5";
    array[9] = ecdh_param;
    ecdh_param.priv =
        "77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848";
    ecdh_param.kcx0 =
        "f75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658";
    ecdh_param.kcy0 =
        "33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c";
    array[10] = ecdh_param;
    ecdh_param.priv =
        "42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e";
    ecdh_param.kcx0 =
        "2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d";
    ecdh_param.kcy0 =
        "62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e";
    array[11] = ecdh_param;
    ecdh_param.priv =
        "ceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b";
    ecdh_param.kcx0 =
        "cd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb";
    ecdh_param.kcy0 =
        "c3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4";
    array[12] = ecdh_param;
    ecdh_param.priv =
        "43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604";
    ecdh_param.kcx0 =
        "15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471";
    ecdh_param.kcy0 =
        "cdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77";
    array[13] = ecdh_param;
    ecdh_param.priv =
        "b2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903";
    ecdh_param.kcx0 =
        "49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1";
    ecdh_param.kcy0 =
        "8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924";
    array[14] = ecdh_param;
    ecdh_param.priv =
        "4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8";
    ecdh_param.kcx0 =
        "19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c";
    ecdh_param.kcy0 =
        "09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae";
    array[15] = ecdh_param;
    ecdh_param.priv =
        "4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147";
    ecdh_param.kcx0 =
        "2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954";
    ecdh_param.kcy0 =
        "6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0";
    array[16] = ecdh_param;
    ecdh_param.priv =
        "1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e";
    ecdh_param.kcx0 =
        "a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767";
    ecdh_param.kcy0 =
        "dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03";
    array[17] = ecdh_param;
    ecdh_param.priv =
        "dd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3";
    ecdh_param.kcx0 =
        "a2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644";
    ecdh_param.kcy0 =
        "563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a";
    array[18] = ecdh_param;
    ecdh_param.priv =
        "5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76";
    ecdh_param.kcx0 =
        "ccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f";
    ecdh_param.kcy0 =
        "e9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38";
    array[19] = ecdh_param;
    ecdh_param.priv =
        "b601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d";
    ecdh_param.kcx0 =
        "c188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e";
    ecdh_param.kcy0 =
        "bf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051";
    array[20] = ecdh_param;
    ecdh_param.priv =
        "fefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535";
    ecdh_param.kcx0 =
        "317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6";
    ecdh_param.kcy0 =
        "09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae";
    array[21] = ecdh_param;
    ecdh_param.priv =
        "334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce";
    ecdh_param.kcx0 =
        "45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1";
    ecdh_param.kcy0 =
        "5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321";
    array[22] = ecdh_param;
    ecdh_param.priv =
        "2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d";
    ecdh_param.kcx0 =
        "a19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6";
    ecdh_param.kcy0 =
        "e9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef";
    array[23] = ecdh_param;
    ecdh_param.priv =
        "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0";
    ecdh_param.kcx0 =
        "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b";
    ecdh_param.kcy0 =
        "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92";
    array[24] = ecdh_param;
    return;
  }
  if (group == secp384r1)
  {
    ecdh_param.priv = "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b681"
                      "8a661774ad463b205da88cf699ab4d43c9cf98a1";
    ecdh_param.kcx0 = "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27f"
                      "e7513272734466b400091adbf2d68c58e0c50066";
    ecdh_param.kcy0 = "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf24"
                      "3451915ed0905a32b060992b468c64766fc8437a";
    array[0] = ecdh_param;
    ecdh_param.priv = "92860c21bde06165f8e900c687f8ef0a05d14f290b3f07d8b3a8cc64"
                      "04366e5d5119cd6d03fb12dc58e89f13df9cd783";
    ecdh_param.kcx0 = "30f43fcf2b6b00de53f624f1543090681839717d53c7c955d1d69efa"
                      "f0349b7363acb447240101cbb3af6641ce4b88e0";
    ecdh_param.kcy0 = "25e46c0c54f0162a77efcc27b6ea792002ae2ba82714299c860857a6"
                      "8153ab62e525ec0530d81b5aa15897981e858757";
    array[1] = ecdh_param;
    ecdh_param.priv = "12cf6a223a72352543830f3f18530d5cb37f26880a0b294482c8a8ef"
                      "8afad09aa78b7dc2f2789a78c66af5d1cc553853";
    ecdh_param.kcx0 = "1aefbfa2c6c8c855a1a216774550b79a24cda37607bb1f7cc906650e"
                      "e4b3816d68f6a9c75da6e4242cebfb6652f65180";
    ecdh_param.kcy0 = "419d28b723ebadb7658fcebb9ad9b7adea674f1da3dc6b6397b55da0"
                      "f61a3eddacb4acdb14441cb214b04a0844c02fa3";
    array[2] = ecdh_param;
    ecdh_param.priv = "8dd48063a3a058c334b5cc7a4ce07d02e5ee6d8f1f3c51a1600962cb"
                      "ab462690ae3cd974fb39e40b0e843daa0fd32de1";
    ecdh_param.kcx0 = "8bc089326ec55b9cf59b34f0eb754d93596ca290fcb3444c83d4de3a"
                      "5607037ec397683f8cef07eab2fe357eae36c449";
    ecdh_param.kcy0 = "d9d16ce8ac85b3f1e94568521aae534e67139e310ec72693526aa2e9"
                      "27b5b322c95a1a033c229cb6770c957cd3148dd7";
    array[3] = ecdh_param;
    ecdh_param.priv = "84ece6cc3429309bd5b23e959793ed2b111ec5cb43b6c18085fcaea9"
                      "efa0685d98a6262ee0d330ee250bc8a67d0e733f";
    ecdh_param.kcx0 = "eb952e2d9ac0c20c6cc48fb225c2ad154f53c8750b003fd3b4ed8ed1"
                      "dc0defac61bcdde02a2bcfee7067d75d342ed2b0";
    ecdh_param.kcy0 = "f1828205baece82d1b267d0d7ff2f9c9e15b69a72df47058a97f3891"
                      "005d1fb38858f5603de840e591dfa4f6e7d489e1";
    array[4] = ecdh_param;
    ecdh_param.priv = "68fce2121dc3a1e37b10f1dde309f9e2e18fac47cd1770951451c348"
                      "4cdb77cb136d00e731260597cc2859601c01a25b";
    ecdh_param.kcx0 = "441d029e244eb7168d647d4df50db5f4e4974ab3fdaf022aff058b36"
                      "95d0b8c814cc88da6285dc6df1ac55c553885003";
    ecdh_param.kcy0 = "e8025ac23a41d4b1ea2aa46c50c6e479946b59b6d76497cd9249977e"
                      "0bfe4a6262622f13d42a3c43d66bdbb30403c345";
    array[5] = ecdh_param;
    ecdh_param.priv = "b1764c54897e7aae6de9e7751f2f37de849291f88f0f91093155b858"
                      "d1cc32a3a87980f706b86cc83f927bdfdbeae0bd";
    ecdh_param.kcx0 = "3d4e6bf08a73404accc1629873468e4269e82d90d832e58ad7214263"
                      "9b5a056ad8d35c66c60e8149fac0c797bceb7c2f";
    ecdh_param.kcy0 = "9b0308dc7f0e6d29f8c277acbc65a21e5adb83d11e6873bc0a07fda0"
                      "997f482504602f59e10bc5cb476b83d0a4f75e71";
    array[6] = ecdh_param;
    ecdh_param.priv = "f0f7a96e70d98fd5a30ad6406cf56eb5b72a510e9f192f50e1f84524"
                      "dbf3d2439f7287bb36f5aa912a79deaab4adea82";
    ecdh_param.kcx0 = "f5f6bef1d110da03be0017eac760cc34b24d092f736f237bc7054b38"
                      "65312a813bcb62d297fb10a4f7abf54708fe2d3d";
    ecdh_param.kcy0 = "06fdf8d7dc032f4e10010bf19cbf6159321252ff415fb91920d438f2"
                      "4e67e60c2eb0463204679fa356af44cea9c9ebf5";
    array[7] = ecdh_param;
    ecdh_param.priv = "9efb87ddc61d43c482ba66e1b143aef678fbd0d1bebc2000941fabe6"
                      "77fe5b706bf78fce36d100b17cc787ead74bbca2";
    ecdh_param.kcx0 = "7cdec77e0737ea37c67b89b7137fe38818010f4464438ee4d1d35a0c"
                      "488cad3fde2f37d00885d36d3b795b9f93d23a67";
    ecdh_param.kcy0 = "28c42ee8d6027c56cf979ba4c229fdb01d234944f8ac433650112c3c"
                      "f0f02844e888a3569dfef7828a8a884589aa055e";
    array[8] = ecdh_param;
    ecdh_param.priv = "d787a57fde22ec656a0a525cf3c738b30d73af61e743ea90893ecb2d"
                      "7b622add2f94ee25c2171467afb093f3f84d0018";
    ecdh_param.kcx0 = "8eeea3a319c8df99fbc29cb55f243a720d95509515ee5cc587a5c5ae"
                      "22fbbd009e626db3e911def0b99a4f7ae304b1ba";
    ecdh_param.kcy0 = "73877dc94db9adddc0d9a4b24e8976c22d73c844370e1ee857f8d1b1"
                      "29a3bd5f63f40caf3bd0533e38a5f5777074ff9e";
    array[9] = ecdh_param;
    ecdh_param.priv = "83d70f7b164d9f4c227c767046b20eb34dfc778f5387e32e834b1e6d"
                      "aec20edb8ca5bb4192093f543b68e6aeb7ce788b";
    ecdh_param.kcx0 = "a721f6a2d4527411834b13d4d3a33c29beb83ab7682465c6cbaf6624"
                      "aca6ea58c30eb0f29dd842886695400d7254f20f";
    ecdh_param.kcy0 = "14ba6e26355109ad35129366d5e3a640ae798505a7fa55a96a36b5da"
                      "d33de00474f6670f522214dd7952140ab0a7eb68";
    array[10] = ecdh_param;
    ecdh_param.priv = "8f558e05818b88ed383d5fca962e53413db1a0e4637eda194f761944"
                      "cbea114ab9d5da175a7d57882550b0e432f395a9";
    ecdh_param.kcx0 = "d882a8505c2d5cb9b8851fc676677bb0087681ad53faceba1738286b"
                      "45827561e7da37b880276c656cfc38b32ade847e";
    ecdh_param.kcy0 = "34b314bdc134575654573cffaf40445da2e6aaf987f7e913cd4c3091"
                      "523058984a25d8f21da8326192456c6a0fa5f60c";
    array[11] = ecdh_param;
    ecdh_param.priv = "0f5dee0affa7bbf239d5dff32987ebb7cf84fcceed643e1d3c62d0b3"
                      "352aec23b6e5ac7fa4105c8cb26126ad2d1892cb";
    ecdh_param.kcx0 = "815c9d773dbf5fb6a1b86799966247f4006a23c92e68c55e9eaa998b"
                      "17d8832dd4d84d927d831d4f68dac67c6488219f";
    ecdh_param.kcy0 = "e79269948b2611484560fd490feec887cb55ef99a4b524880fa7499d"
                      "6a07283aae2afa33feab97deca40bc606c4d8764";
    array[12] = ecdh_param;
    ecdh_param.priv = "037b633b5b8ba857c0fc85656868232e2febf59578718391b81da854"
                      "1a00bfe53c30ae04151847f27499f8d7abad8cf4";
    ecdh_param.kcx0 = "1c0eeda7a2be000c5bdcda0478aed4db733d2a9e341224379123ad84"
                      "7030f29e3b168fa18e89a3c0fba2a6ce1c28fc3b";
    ecdh_param.kcy0 = "ec8c1c83c118c4dbea94271869f2d868eb65e8b44e21e6f14b0f4d9b"
                      "38c068daefa27114255b9a41d084cc4a1ad85456";
    array[13] = ecdh_param;
    ecdh_param.priv = "e3d07106bedcc096e7d91630ffd3094df2c7859db8d7edbb2e37b4ac"
                      "47f429a637d06a67d2fba33838764ef203464991";
    ecdh_param.kcx0 = "c95c185e256bf997f30b311548ae7f768a38dee43eeeef43083f3077"
                      "be70e2bf39ac1d4daf360c514c8c6be623443d1a";
    ecdh_param.kcy0 = "3e63a663eaf75d8a765ab2b9a35513d7933fa5e26420a5244550ec6c"
                      "3b6f033b96db2aca3d6ac6aab052ce929595aea5";
    array[14] = ecdh_param;
    ecdh_param.priv = "f3f9b0c65a49a506632c8a45b10f66b5316f9eeb06fae218f2da6233"
                      "3f99905117b141c760e8974efc4af10570635791";
    ecdh_param.kcx0 = "3497238a7e6ad166df2dac039aa4dac8d17aa925e7c7631eb3b56e3a"
                      "aa1c545fcd54d2e5985807910fb202b1fc191d2a";
    ecdh_param.kcy0 = "a49e5c487dcc7aa40a8f234c979446040d9174e3ad357d404d776518"
                      "3195aed3f913641b90c81a306ebf0d8913861316";
    array[15] = ecdh_param;
    ecdh_param.priv = "59fce7fad7de28bac0230690c95710c720e528f9a4e54d3a6a8cd5fc"
                      "5c5f21637031ce1c5b4e3d39647d8dcb9b794664";
    ecdh_param.kcx0 = "90a34737d45b1aa65f74e0bd0659bc118f8e4b774b761944ffa6573c"
                      "6df4f41dec0d11b697abd934d390871d4b453240";
    ecdh_param.kcy0 = "9b590719bb3307c149a7817be355d684893a307764b512eeffe07cb6"
                      "99edb5a6ffbf8d6032e6c79d5e93e94212c2aa4e";
    array[16] = ecdh_param;
    ecdh_param.priv = "3e49fbf950a424c5d80228dc4bc35e9f6c6c0c1d04440998da0a609a"
                      "877575dbe437d6a5cedaa2ddd2a1a17fd112aded";
    ecdh_param.kcx0 = "dda546acfc8f903d11e2e3920669636d44b2068aeb66ff07aa266f00"
                      "30e1535b0ed0203cb8a460ac990f1394faf22f1d";
    ecdh_param.kcy0 = "15bbb2597913035faadf413476f4c70f7279769a40c986f470c427b4"
                      "ee4962abdf8173bbad81874772925fd32f0b159f";
    array[17] = ecdh_param;
    ecdh_param.priv = "50ccc1f7076e92f4638e85f2db98e0b483e6e2204c92bdd440a6deea"
                      "04e37a07c6e72791c190ad4e4e86e01efba84269";
    ecdh_param.kcx0 = "788be2336c52f4454d63ee944b1e49bfb619a08371048e6da92e584e"
                      "ae70bde1f171c4df378bd1f3c0ab03048a237802";
    ecdh_param.kcy0 = "4673ebd8db604eaf41711748bab2968a23ca4476ce144e728247f08a"
                      "f752929157b5830f1e26067466bdfa8b65145a33";
    array[18] = ecdh_param;
    ecdh_param.priv = "06f132b71f74d87bf99857e1e4350a594e5fe35533b888552ceccbc0"
                      "d8923c902e36141d7691e28631b8bc9bafe5e064";
    ecdh_param.kcx0 = "d09bb822eb99e38060954747c82bb3278cf96bbf36fece3400f4c873"
                      "838a40c135eb3babb9293bd1001bf3ecdee7bf26";
    ecdh_param.kcy0 = "d416db6e1b87bbb7427788a3b6c7a7ab2c165b1e366f9608df512037"
                      "584f213a648d47f16ac326e19aae972f63fd76c9";
    array[19] = ecdh_param;
    ecdh_param.priv = "12048ebb4331ec19a1e23f1a2c773b664ccfe90a28bfb846fc12f81d"
                      "ff44b7443c77647164bf1e9e67fd2c07a6766241";
    ecdh_param.kcx0 = "13741262ede5861dad71063dfd204b91ea1d3b7c631df68eb9499695"
                      "27d79a1dc59295ef7d2bca6743e8cd77b04d1b58";
    ecdh_param.kcy0 = "0baaeadc7e19d74a8a04451a135f1be1b02fe299f9dc00bfdf201e83"
                      "d995c6950bcc1cb89d6f7b30bf54656b9a4da586";
    array[20] = ecdh_param;
    ecdh_param.priv = "34d61a699ca576169fcdc0cc7e44e4e1221db0fe63d16850c8104029"
                      "f7d48449714b9884328cae189978754ab460b486";
    ecdh_param.kcx0 = "9e22cbc18657f516a864b37b783348b66f1aa9626cd631f4fa1bd32a"
                      "d88cf11db52057c660860d39d11fbf024fabd444";
    ecdh_param.kcy0 = "6b0d53c79681c28116df71e9cee74fd56c8b7f04b39f1198cc72284e"
                      "98be9562e35926fb4f48a9fbecafe729309e8b6f";
    array[21] = ecdh_param;
    ecdh_param.priv = "dc60fa8736d702135ff16aab992bb88eac397f5972456c72ec447374"
                      "d0d8ce61153831bfc86ad5a6eb5b60bfb96a862c";
    ecdh_param.kcx0 = "2db5da5f940eaa884f4db5ec2139b0469f38e4e6fbbcc52df15c0f7c"
                      "f7fcb1808c749764b6be85d2fdc5b16f58ad5dc0";
    ecdh_param.kcy0 = "22e8b02dcf33e1b5a083849545f84ad5e43f77cb71546dbbac0d11bd"
                      "b2ee202e9d3872e8d028c08990746c5e1dde9989";
    array[22] = ecdh_param;
    ecdh_param.priv = "6fa6a1c704730987aa634b0516a826aba8c6d6411d3a4c89772d7a62"
                      "610256a2e2f289f5c3440b0ec1e70fa339e251ce";
    ecdh_param.kcx0 = "329647baa354224eb4414829c5368c82d7893b39804e08cbb2180f45"
                      "9befc4b347a389a70c91a23bd9d30c83be5295d3";
    ecdh_param.kcy0 = "cc8f61923fad2aa8e505d6cfa126b9fabd5af9dce290b75660ef06d1"
                      "caa73681d06089c33bc4246b3aa30dbcd2435b12";
    array[23] = ecdh_param;
    ecdh_param.priv = "74ad8386c1cb2ca0fcdeb31e0869bb3f48c036afe2ef110ca302bc8b"
                      "910f621c9fcc54cec32bb89ec7caa84c7b8e54a8";
    ecdh_param.kcx0 = "29d8a36d22200a75b7aea1bb47cdfcb1b7fd66de967041434728ab5d"
                      "533a060df732130600fe6f75852a871fb2938e39";
    ecdh_param.kcy0 = "e19b53db528395de897a45108967715eb8cb55c3fcbf23379372c087"
                      "3a058d57544b102ecce722b2ccabb1a603774fd5";
    array[24] = ecdh_param;
    return;
  }
  if (group == secp521r1)
  {
    ecdh_param.priv = "0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcc"
                      "e802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb9"
                      "5d5ce31ddcb6f9edb4d6fc47";
    ecdh_param.kcx0 = "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f"
                      "3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37"
                      "c09870ebf176666877a2046d";
    ecdh_param.kcy0 = "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe0540069794"
                      "2e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6"
                      "c3e522497955a4f3c302f676";
    array[0] = ecdh_param;
    ecdh_param.priv = "000000816f19c1fb10ef94d4a1d81c156ec3d1de08b66761f03f06ee"
                      "4bb9dcebbbfe1eaa1ed49a6a990838d8ed318c14d74cc872f95d05d0"
                      "7ad50f621ceb620cd905cfb8";
    ecdh_param.kcx0 = "000001df277c152108349bc34d539ee0cf06b24f5d3500677b444545"
                      "3ccc21409453aafb8a72a0be9ebe54d12270aa51b3ab7f316aa5e74a"
                      "951c5e53f74cd95fc29aee7a";
    ecdh_param.kcy0 = "0000013d52f33a9f3c14384d1587fa8abe7aed74bc33749ad9c570b4"
                      "71776422c7d4505d9b0a96b3bfac041e4c6a6990ae7f700e5b4a6640"
                      "229112deafa0cd8bb0d089b0";
    array[1] = ecdh_param;
    ecdh_param.priv = "0000012f2e0c6d9e9d117ceb9723bced02eb3d4eebf5feeaf8ee0113"
                      "ccd8057b13ddd416e0b74280c2d0ba8ed291c443bc1b141caf8afb3a"
                      "71f97f57c225c03e1e4d42b0";
    ecdh_param.kcx0 = "00000092db3142564d27a5f0006f819908fba1b85038a5bc2509906a"
                      "497daac67fd7aee0fc2daba4e4334eeaef0e0019204b471cd88024f8"
                      "2115d8149cc0cf4f7ce1a4d5";
    ecdh_param.kcy0 = "0000016bad0623f517b158d9881841d2571efbad63f85cbe2e581960"
                      "c5d670601a6760272675a548996217e4ab2b8ebce31d71fca63fcc3c"
                      "08e91c1d8edd91cf6fe845f8";
    array[2] = ecdh_param;
    ecdh_param.priv = "000000e548a79d8b05f923b9825d11b656f222e8cb98b0f89de1d317"
                      "184dc5a698f7c71161ee7dc11cd31f4f4f8ae3a981e1a3e78bdebb97"
                      "d7c204b9261b4ef92e0918e0";
    ecdh_param.kcx0 = "000000fdd40d9e9d974027cb3bae682162eac1328ad61bc4353c45bf"
                      "5afe76bf607d2894c8cce23695d920f2464fda4773d4693be4b37735"
                      "84691bdb0329b7f4c86cc299";
    ecdh_param.kcy0 = "00000034ceac6a3fef1c3e1c494bfe8d872b183832219a7e14da414d"
                      "4e3474573671ec19b033be831b915435905925b44947c592959945b4"
                      "eb7c951c3b9c8cf52530ba23";
    array[3] = ecdh_param;
    ecdh_param.priv = "000001c8aae94bb10b8ca4f7be577b4fb32bb2381032c4942c24fc2d"
                      "753e7cc5e47b483389d9f3b956d20ee9001b1eef9f23545f72c56021"
                      "40046839e963313c3decc864";
    ecdh_param.kcx0 = "00000098d99dee0816550e84dbfced7e88137fddcf581a725a455021"
                      "115fe49f8dc3cf233cd9ea0e6f039dc7919da973cdceaca205da39e0"
                      "bd98c8062536c47f258f44b5";
    ecdh_param.kcy0 = "000000cd225c8797371be0c4297d2b457740100c774141d8f214c23b"
                      "61aa2b6cd4806b9b70722aa4965fb622f42b7391e27e5ec21c5679c5"
                      "b06b59127372997d421adc1e";
    array[4] = ecdh_param;
    ecdh_param.priv = "0000009b0af137c9696c75b7e6df7b73156bb2d45f482e5a4217324f"
                      "478b10ceb76af09724cf86afa316e7f89918d31d54824a5c33107a48"
                      "3c15c15b96edc661340b1c0e";
    ecdh_param.kcx0 = "0000007ae115adaaf041691ab6b7fb8c921f99d8ed32d283d67084e8"
                      "0b9ad9c40c56cd98389fb0a849d9ecf7268c297b6f93406119f40e32"
                      "b5773ed25a28a9a85c4a7588";
    ecdh_param.kcy0 = "000001a28e004e37eeaefe1f4dbb71f1878696141af3a10a9691c4ed"
                      "93487214643b761fa4b0fbeeb247cf6d3fba7a60697536ad03f49b80"
                      "a9d1cb079673654977c5fa94";
    array[5] = ecdh_param;
    ecdh_param.priv = "000001e48faacee6dec83ffcde944cf6bdf4ce4bae72747888ebafee"
                      "455b1e91584971efb49127976a52f4142952f7c207ec0265f2b718cf"
                      "3ead96ea4f62c752e4f7acd3";
    ecdh_param.kcx0 = "0000012588115e6f7f7bdcfdf57f03b169b479758baafdaf569d0413"
                      "5987b2ce6164c02a57685eb5276b5dae6295d3fe90620f38b5535c6d"
                      "2260c173e61eb888ca920203";
    ecdh_param.kcy0 = "000001542c169cf97c2596fe2ddd848a222e367c5f7e6267ebc1bcd9"
                      "ab5dcf49158f1a48e4af29a897b7e6a82091c2db874d8e7abf0f5806"
                      "4691344154f396dbaed188b6";
    array[6] = ecdh_param;
    ecdh_param.priv = "000000c29aa223ea8d64b4a1eda27f39d3bc98ea0148dd98c1cbe595"
                      "f8fd2bfbde119c9e017a50f5d1fc121c08c1cef31b758859556eb3e0"
                      "e042d8dd6aaac57a05ca61e3";
    ecdh_param.kcx0 = "00000169491d55bd09049fdf4c2a53a660480fee4c03a0538675d1cd"
                      "09b5bba78dac48543ef118a1173b3fbf8b20e39ce0e6b890a163c50f"
                      "9645b3d21d1cbb3b60a6fff4";
    ecdh_param.kcy0 = "00000083494b2eba76910fed33c761804515011fab50e3b377abd8a8"
                      "a045d886d2238d2c268ac1b6ec88bd71b7ba78e2c33c152e4bf7da5d"
                      "565e4acbecf5e92c7ad662bb";
    array[7] = ecdh_param;
    ecdh_param.priv = "00000028692be2bf5c4b48939846fb3d5bce74654bb2646e15f8389e"
                      "23708a1afadf561511ea0d9957d0b53453819d60fba8f65a18f7b29d"
                      "f021b1bb01cd163293acc3cc";
    ecdh_param.kcx0 = "0000008415f5bbd0eee387d6c09d0ef8acaf29c66db45d6ba101860a"
                      "e45d3c60e1e0e3f7247a4626a60fdd404965c3566c79f6449e856ce0"
                      "bf94619f97da8da24bd2cfb6";
    ecdh_param.kcy0 = "000000fdd7c59c58c361bc50a7a5d0d36f723b17c4f2ad2b03c24d42"
                      "dc50f74a8c465a0afc4683f10fab84652dfe9e928c2626b5456453e1"
                      "573ff60be1507467d431fbb2";
    array[8] = ecdh_param;
    ecdh_param.priv = "000001194d1ee613f5366cbc44b504d21a0cf6715e209cd358f2dd5f"
                      "3e71cc0d67d0e964168c42a084ebda746f9863a86bacffc819f1edf1"
                      "b8c727ccfb3047240a57c435";
    ecdh_param.kcx0 = "000001c721eea805a5cba29f34ba5758775be0cf6160e6c08723f5ab"
                      "17bf96a1ff2bd9427961a4f34b07fc0b14ca4b2bf6845debd5a869f1"
                      "24ebfa7aa72fe565050b7f18";
    ecdh_param.kcy0 = "000000b6e89eb0e1dcf181236f7c548fd1a8c16b258b52c1a9bfd3fe"
                      "8f22841b26763265f074c4ccf2d634ae97b701956f67a11006c52d97"
                      "197d92f585f5748bc2672eeb";
    array[9] = ecdh_param;
    ecdh_param.priv = "000001fd90e3e416e98aa3f2b6afa7f3bf368e451ad9ca5bd54b5b14"
                      "aee2ed6723dde5181f5085b68169b09fbec721372ccf6b284713f9a6"
                      "356b8d560a8ff78ca3737c88";
    ecdh_param.kcx0 = "000001c35823e440a9363ab98d9fc7a7bc0c0532dc7977a79165599b"
                      "f1a9cc64c00fb387b42cca365286e8430360bfad3643bc31354eda50"
                      "dc936c329ecdb60905c40fcb";
    ecdh_param.kcy0 = "000000d9e7f433531e44df4f6d514201cbaabb06badd6783e0111172"
                      "6d815531d233c5cdb722893ffbb2027259d594de77438809738120c6"
                      "f783934f926c3fb69b40c409";
    array[10] = ecdh_param;
    ecdh_param.priv = "0000009012ecfdadc85ced630afea534cdc8e9d1ab8be5f3753dcf5f"
                      "2b09b40eda66fc6858549bc36e6f8df55998cfa9a0703aecf6c42799"
                      "c245011064f530c09db98369";
    ecdh_param.kcx0 = "000000093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9be"
                      "eed87d6995f54918ec6619b9931955d5a89d4d74adf1046bb362192f"
                      "2ef6bd3e3d2d04dd1f87054a";
    ecdh_param.kcy0 = "000000aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f"
                      "19983c44674fe15327acaac1fa40424c395a6556cb8167312527fae5"
                      "865ecffc14bbdc17da78cdcf";
    array[11] = ecdh_param;
    ecdh_param.priv = "000001b5ff847f8eff20b88cfad42c06e58c3742f2f8f1fdfd64b539"
                      "ba48c25926926bd5e332b45649c0b184f77255e9d58fe8afa1a6d968"
                      "e2cb1d4637777120c765c128";
    ecdh_param.kcx0 = "00000083192ed0b1cb31f75817794937f66ad91cf74552cd510cedb9"
                      "fd641310422af5d09f221cad249ee814d16dd7ac84ded9eacdc28340"
                      "fcfc9c0c06abe30a2fc28cd8";
    ecdh_param.kcy0 = "0000002212ed868c9ba0fb2c91e2c39ba93996a3e4ebf45f2852d092"
                      "8c48930e875cc7b428d0e7f3f4d503e5d60c68cb49b13c2480cd486b"
                      "ed9200caddaddfe4ff8e3562";
    array[12] = ecdh_param;
    ecdh_param.priv = "0000011a6347d4e801c91923488354cc533e7e35fddf81ff0fb7f56b"
                      "b0726e0c29ee5dcdc5f394ba54cf57269048aab6e055895c8da24b8b"
                      "0639a742314390cc04190ed6";
    ecdh_param.kcx0 = "000001a89b636a93e5d2ba6c2292bf23033a84f06a3ac1220ea71e80"
                      "6afbe097a804cc67e9baa514cfb6c12c9194be30212bf7aae7fdf6d3"
                      "76c212f0554e656463ffab7e";
    ecdh_param.kcy0 = "00000182efcaf70fc412d336602e014da47256a0b606f2addcce8053"
                      "bf817ac8656bb4e42f14c8cbf2a68f488ab35dcdf64056271dee1f60"
                      "6a440ba4bd4e5a11b8b8e54f";
    array[13] = ecdh_param;
    ecdh_param.priv = "00000022b6d2a22d71dfaa811d2d9f9f31fbed27f2e1f3d239538ddf"
                      "3e4cc8c39a330266db25b7bc0a9704f17bde7f3592bf5f1f2d4b5601"
                      "3aacc3d8d1bc02f00d3146cc";
    ecdh_param.kcx0 = "0000017200b3f16a68cbaed2bf78ba8cddfb6cffac262bba00fbc25f"
                      "9dc72a07ce59372904899f364c44cb264c097b647d4412bee3e51989"
                      "2d534d9129f8a28f7500fee7";
    ecdh_param.kcy0 = "000000baba8d672a4f4a3b63de48b96f56e18df5d68f7d70d5109833"
                      "f43770d6732e06b39ad60d93e5b43db8789f1ec0aba47286a39ea584"
                      "235acea757dbf13d53b58364";
    array[14] = ecdh_param;
    ecdh_param.priv = "0000005bacfff268acf6553c3c583b464ea36a1d35e2b257a5d49eb3"
                      "419d5a095087c2fb4d15cf5bf5af816d0f3ff7586490ccd3ddc1a98b"
                      "39ce63749c6288ce0dbdac7d";
    ecdh_param.kcx0 = "0000004efd5dbd2f979e3831ce98f82355d6ca14a575784287588299"
                      "0ab85ab9b7352dd6b9b2f4ea9a1e95c3880d65d1f3602f9ca653dc34"
                      "6fac858658d75626f4d4fb08";
    ecdh_param.kcy0 = "00000061cf15dbdaa7f31589c98400373da284506d70c89f074ed262"
                      "a9e28140796b7236c2eef99016085e71552ff488c72b7339fefb7915"
                      "c38459cb20ab85aec4e45052";
    array[15] = ecdh_param;
    ecdh_param.priv = "0000008e2c93c5423876223a637cad367c8589da69a2d0fc68612f31"
                      "923ae50219df2452e7cc92615b67f17b57ffd2f52b19154bb40d7715"
                      "336420fde2e89fee244f59dc";
    ecdh_param.kcx0 = "00000129891de0cf3cf82e8c2cf1bf90bb296fe00ab08ca45bb7892e"
                      "0e227a504fdd05d2381a4448b68adff9c4153c87eacb78330d8bd525"
                      "15f9f9a0b58e85f446bb4e10";
    ecdh_param.kcy0 = "0000009edd679696d3d1d0ef327f200383253f6413683d9e4fcc87bb"
                      "35f112c2f110098d15e5701d7ceee416291ff5fed85e687f727388b9"
                      "afe26a4f6feed560b218e6bb";
    array[16] = ecdh_param;
    ecdh_param.priv = "00000004d49d39d40d8111bf16d28c5936554326b197353eebbcf475"
                      "45393bc8d3aaf98f14f5be7074bfb38e6cc97b989754074daddb3045"
                      "f4e4ce745669fdb3ec0d5fa8";
    ecdh_param.kcx0 = "000001a3c20240e59f5b7a3e17c275d2314ba1741210ad58b71036f8"
                      "c83cc1f6b0f409dfdd9113e94b67ec39c3291426c23ffcc447054670"
                      "d2908ff8fe67dc2306034c5c";
    ecdh_param.kcy0 = "000001d2825bfd3af8b1e13205780c137fe938f84fde40188e61ea02"
                      "cead81badfdb425c29f7d7fb0324debadc10bbb93de68f62c3506926"
                      "8283f5265865db57a79f7bf7";
    array[17] = ecdh_param;
    ecdh_param.priv = "0000011a5d1cc79cd2bf73ea106f0e60a5ace220813b53e27b739864"
                      "334a07c03367efda7a4619fa6eef3a9746492283b3c445610a023a9c"
                      "c49bf4591140384fca5c8bb5";
    ecdh_param.kcx0 = "0000007e2d138f2832e345ae8ff65957e40e5ec7163f016bdf6d24a2"
                      "243daa631d878a4a16783990c722382130f9e51f0c1bd6ff5ac96780"
                      "e48b68f5dec95f42e6144bb5";
    ecdh_param.kcy0 = "000000b0de5c896791f52886b0f09913e26e78dd0b69798fc4df6d95"
                      "e3ca708ecbcbcce1c1895f5561bbabaae372e9e67e6e1a3be60e19b4"
                      "70cdf673ec1fc393d3426e20";
    array[18] = ecdh_param;
    ecdh_param.priv = "0000010c908caf1be74c616b625fc8c1f514446a6aec83b5937141d6"
                      "afbb0a8c7666a7746fa1f7a6664a2123e8cdf6cd8bf836c56d3c0ebd"
                      "cc980e43a186f938f3a78ae7";
    ecdh_param.kcx0 = "000000118c36022209b1af8ebad1a12b566fc48744576e1199fe80de"
                      "1cdf851cdf03e5b9091a8f7e079e83b7f827259b691d0c22ee29d6bd"
                      "f73ec7bbfd746f2cd97a357d";
    ecdh_param.kcy0 = "000000da5ff4904548a342e2e7ba6a1f4ee5f840411a96cf63e6fe62"
                      "2f22c13e614e0a847c11a1ab3f1d12cc850c32e095614ca8f7e27214"
                      "77b486e9ff40372977c3f65c";
    array[19] = ecdh_param;
    ecdh_param.priv = "000001b37d6b7288de671360425d3e5ac1ccb21815079d8d73431e9b"
                      "74a6f0e7ae004a357575b11ad66642ce8b775593eba9d98bf25c75ef"
                      "0b4d3a2098bbc641f59a2b77";
    ecdh_param.kcx0 = "000001780edff1ca1c03cfbe593edc6c049bcb2860294a92c355489d"
                      "9afb2e702075ade1c953895a456230a0cde905de4a3f38573dbfcccd"
                      "67ad6e7e93f0b5581e926a5d";
    ecdh_param.kcy0 = "000000a5481962c9162962e7f0ebdec936935d0eaa813e8226d40d7f"
                      "6119bfd940602380c86721e61db1830f51e139f210000bcec0d8edd3"
                      "9e54d73a9a129f95cd5fa979";
    array[20] = ecdh_param;
    ecdh_param.priv = "000000f2661ac762f60c5fff23be5d969ccd4ec6f98e4e72618d12bd"
                      "cdb9b4102162333788c0bae59f91cdfc172c7a1681ee44d96ab2135a"
                      "6e5f3415ebbcd55165b1afb0";
    ecdh_param.kcx0 = "0000016dacffa183e5303083a334f765de724ec5ec9402026d479788"
                      "4a9828a0d321a8cfac74ab737fe20a7d6befcfc73b6a35c1c7b01d37"
                      "3e31abc192d48a4241a35803";
    ecdh_param.kcy0 = "0000011e5327cac22d305e7156e559176e19bee7e4f2f59e86f1a9d0"
                      "b6603b6a7df1069bde6387feb71587b8ffce5b266e1bae86de29378a"
                      "34e5c74b6724c4d40a719923";
    array[21] = ecdh_param;
    ecdh_param.priv = "000000f430ca1261f09681a9282e9e970a9234227b1d5e58d558c3cc"
                      "6eff44d1bdf53de16ad5ee2b18b92d62fc79586116b0efc15f79340f"
                      "b7eaf5ce6c44341dcf8dde27";
    ecdh_param.kcx0 = "000000a091421d3703e3b341e9f1e7d58f8cf7bdbd1798d001967b80"
                      "1d1cec27e605c580b2387c1cb464f55ce7ac80334102ab03cfb86d88"
                      "af76c9f4129c01bedd3bbfc4";
    ecdh_param.kcy0 = "0000008c9c577a8e6fc446815e9d40baa66025f15dae285f19eb668e"
                      "e60ae9c98e7ecdbf2b2a68e22928059f67db188007161d3ecf397e08"
                      "83f0c4eb7eaf7827a62205cc";
    array[22] = ecdh_param;
    ecdh_param.priv = "0000005dc33aeda03c2eb233014ee468dff753b72f73b00991043ea3"
                      "53828ae69d4cd0fadeda7bb278b535d7c57406ff2e6e473a5a4ff98e"
                      "90f90d6dadd25100e8d85666";
    ecdh_param.kcx0 = "0000004f38816681771289ce0cb83a5e29a1ab06fc91f786994b2370"
                      "8ff08a08a0f675b809ae99e9f9967eb1a49f196057d69e50d6dedb4d"
                      "d2d9a81c02bdcc8f7f518460";
    ecdh_param.kcy0 = "0000009efb244c8b91087de1eed766500f0e81530752d469256ef79f"
                      "6b965d8a2232a0c2dbc4e8e1d09214bab38485be6e357c4200d073b5"
                      "2f04e4a16fc6f5247187aecb";
    array[23] = ecdh_param;
    ecdh_param.priv = "000000df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a"
                      "655d5fbe16e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2a"
                      "e89957cba3a57a23933e5a78";
    ecdh_param.kcx0 = "000001a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda"
                      "308b359dbbc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb768413"
                      "2795c478ad6f962e4a6f446d";
    ecdh_param.kcy0 = "0000017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9"
                      "d387df67cde85003e0e427552f1cd09059aad0262e235cce5fba8ced"
                      "c4fdc1463da76dcd4b6d1a46";
    array[24] = ecdh_param;
    return;
  }
}


