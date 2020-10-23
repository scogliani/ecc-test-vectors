#include <create_ecc.h>
#include <ecc_pointmul.h>
#include <ecdh_kat.h>

#include <openssl/err.h>

#include <string.h>

int main(int argc, char** argv)
{
  if (argc != 2)
  {
    return -1;
  }

  EC_GROUP* secp192r1 =
      create_ecc("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                 "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
                 "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                 "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                 "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
                 "01");

  EC_GROUP* secp224r1 =
      create_ecc("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
                 "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
                 "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
                 "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
                 "01");

  EC_GROUP* secp256r1 = create_ecc(
      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
      "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
      "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
      "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
      "01");

  EC_GROUP* secp384r1 = create_ecc(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF"
      "0000000000000000FFFFFFFF",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF"
      "0000000000000000FFFFFFFC",
      "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D"
      "8A2ED19D2A85C8EDD3EC2AEF",
      "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25D"
      "BF55296C3A545E3872760AB7",
      "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE"
      "1D7E819D7A431D7C90EA0E5F",
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB2"
      "48B0A77AECEC196ACCC52973",
      "01");

  EC_GROUP* secp521r1 = create_ecc(
      "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
      "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
      "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E15619"
      "3951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
      "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B"
      "5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
      "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE"
      "72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
      "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA5186"
      "8783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
      "01");

  EC_GROUP* frp256v1 = create_ecc(
      "F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03",
      "F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00",
      "EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F",
      "B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF",
      "6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB",
      "F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1",
      "01");

  if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) &&
        (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))))
  {
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
  }
  else
  {
    CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
  }
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE);
  ERR_load_crypto_strings();

  fprintf(stdout, "[%s]\n", argv[1]);
  
  if (!strncmp("secp192r1", argv[1], 9))
  {
#if defined(ECC_POINTMUL)
    ecc_pointmul(secp192r1);
#elif defined(ECDH)
    ecdh_kat(secp192r1,
             "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
             "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
             "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523");

    ecdh_kat(secp192r1,
             "56e853349d96fe4c442448dacb7cf92bb7a95dcf574a9bd5",
             "deb5712fa027ac8d2f22c455ccb73a91e17b6512b5e030e7",
             "7e2690a02cc9b28708431a29fb54b87b1f0c14e011ac2125");

    ecdh_kat(secp192r1,
             "c6ef61fe12e80bf56f2d3f7d0bb757394519906d55500949",
             "4edaa8efc5a0f40f843663ec5815e7762dddc008e663c20f",
             "0a9f8dc67a3e60ef6d64b522185d03df1fc0adfd42478279");

    ecdh_kat(secp192r1,
             "e6747b9c23ba7044f38ff7e62c35e4038920f5a0163d3cda",
             "8887c276edeed3e9e866b46d58d895c73fbd80b63e382e88",
             "04c5097ba6645e16206cfb70f7052655947dd44a17f1f9d5");

    ecdh_kat(secp192r1,
             "beabedd0154a1afcfc85d52181c10f5eb47adc51f655047d",
             "0d045f30254adc1fcefa8a5b1f31bf4e739dd327cd18d594",
             "542c314e41427c08278a08ce8d7305f3b5b849c72d8aff73");

    ecdh_kat(secp192r1,
             "cf70354226667321d6e2baf40999e2fd74c7a0f793fa8699",
             "fb35ca20d2e96665c51b98e8f6eb3d79113508d8bccd4516",
             "368eec0d5bfb847721df6aaff0e5d48c444f74bf9cd8a5a7");

    ecdh_kat(secp192r1,
             "fe942515237fffdd7b4eb5c64909eee4856a076cdf12bae2",
             "824752960c1307e5f13a83da21c7998ca8b5b00b9549f6d0",
             "bc52d91e234363bc32ee0b6778f25cd8c1847510f4348b94");

    ecdh_kat(secp192r1,
             "33fed10492afa5bea0333c0af12cac940c4d222455bcd0fe",
             "10bb57020291141981f833b4749e5611034b308e84011d21",
             "e1cacd6b7bd17ed8ddb50b6aee0654c35f2d0eddc1cffcf6");

    ecdh_kat(secp192r1,
             "f3557c5d70b4c7954960c33568776adbe8e43619abe26b13",
             "5192fce4185a7758ea1bc56e0e4f4e8b2dce32348d0dced1",
             "20989981beaaf0006d88a96e7971a2fa3a33ba46047fc7ba");

    ecdh_kat(secp192r1,
             "586cfba1c6e81766ed52828f177b1be14ebbc5b83348c311",
             "26d019dbe279ead01eed143a91601ada26e2f42225b1c62b",
             "6ca653f08272e0386fc9421fbd580093d7ae6301bca94476");

    ecdh_kat(secp192r1,
             "cad8100603a4f65be08d8fc8a1b7e884c5ff65deb3c96d99",
             "539bc40fe20a0fb267888b647b03eaaf6ec20c02a1e1f8c8",
             "69095e5bb7b4d44c3278a7ee6beca397c45246da9a34c8be");

    ecdh_kat(secp192r1,
             "1edd879cc5c79619cae6c73a691bd5a0395c0ef3b356fcd2",
             "5d343ddb96318fb4794d10f6c573f99fee5d0d57b996250f",
             "99fbdf9d97dd88ad410235dac36e5b92ce2824b8e587a82c");

    ecdh_kat(secp192r1,
             "460e452273fe1827602187ad3bebee65cb84423bb4f47537",
             "8d3db9bdce137ffbfb891388c37df6c0cbc90aa5e5376220",
             "135d30b5cb660eef8764ffc744f15c1b5d6dc06ba4416d37");

    ecdh_kat(secp192r1,
             "b970365008456f8758ecc5a3b33cf3ae6a8d568107a52167",
             "9e0a6949519c7f5be68c0433c5fdf13064aa13fb29483dc3",
             "e1c8ba63e1f471db23185f50d9c871edea21255b3a63b4b7");

    ecdh_kat(secp192r1,
             "59c15b8a2464e41dfe4371c7f7dadf470ae425544f8113bd",
             "be088238902e9939b3d054eeeb8492daf4bdcf09a2ab77f1",
             "58d6749a3a923dc80440f2661fd35b651617e65294b46375");

    ecdh_kat(secp192r1,
             "a6e9b885c66b959d1fc2708d591b6d3228e49eb98f726d61",
             "bf5ae05025e1be617e666d87a4168363873d5761b376b503",
             "e1e6e38b372b6bee0ff5b3502d83735e3b2c26825e4f0fcc");

    ecdh_kat(secp192r1,
             "bdb754096ffbfbd8b0f3cb046ccb7ca149c4e7192067a3ee",
             "6cc4feed84c7ab0d09005d660ed34de6955a9461c4138d11",
             "31225f33864ed48da06fa45a913b46cf42557742e35085e6");

    ecdh_kat(secp192r1,
             "d5bcf2534dafc3d99964c7bd63ab7bd15999fe56dd969c42",
             "36157315bee7afedded58c4e8ba14d3421c401e51135bcc9",
             "37c297ca703f77c52bb062d8ce971db84097ba0c753a418f");

    ecdh_kat(secp192r1,
             "43d4b9df1053be5b4268104c02244d3bf9594b010b46a8b2",
             "98464d47f0256f8292e027e8c92582ea77cf9051f5ce8e5d",
             "449552ef7578be96236fe5ed9d0643c0bb6c5a9134b0108d");

    ecdh_kat(secp192r1,
             "94cac2c2ca714746401670d94edbf3f677867b5a03bee7ad",
             "563eb66c334cf6f123bf04c7803b48a3110214237e983bf5",
             "0f351104819199ef07c9a6051d20758f3af79027ea66a53f");

    ecdh_kat(secp192r1,
             "2a3a9e33c8cc3107a9f9265c3bdea1206570e86f92ac7014",
             "86828c4ac92b5507618aec7873a1d4fc6543c5be33cf3078",
             "b22ca72437545e10d6d4f052422eb898b737a4b8543ee550");

    ecdh_kat(secp192r1,
             "4a6b78a98ac98fa8e99a8ece08ec0251125f85c6fd0e289b",
             "6700a102437781a9581da2bc25ced5abf419da91d3c803df",
             "71396c9cf08bcd91854e3e6e42d8c657ce0f27ab77a9dc4b");

    ecdh_kat(secp192r1,
             "c5a6491d78844d6617ef33be6b8bd54da221450885d5950f",
             "a82f354cf97bee5d22dc6c079f2902ead44d96a8f614f178",
             "a654a9aa8a1a0802f2ce0ee8a0f4ebe96dee1b37464b1ff2");

    ecdh_kat(secp192r1,
             "2ba2703c5e23f6463c5b88dc37292fabd3399b5e1fb67c05",
             "3cec21b28668a12a2cf78e1a8e55d0efe065152fffc34718",
             "1029557beba4ff1992bd21c23cb4825f6dae70e3318fd1ca");

    ecdh_kat(secp192r1,
             "836118c6248f882e9147976f764826c1a28755a6102977d5",
             "7082644715b8b731f8228b5118e7270d34d181f361a221fc",
             "464649d6c88ca89614488a1cc7b8442bb42f9fb3020a3d76");
#endif
  }
  else if (!strncmp("secp224r1", argv[1], 9))
  {
    ecc_pointmul(secp224r1);
  } else if (!strncmp("secp256r1", argv[1], 9)) {
#if defined(ECC_POINTMUL)
    ecc_pointmul(secp256r1);
#elif defined(ECDH)
    ecdh_kat(
        secp256r1,
        "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");

    ecdh_kat(
        secp256r1,
        "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5",
        "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
        "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3");

    ecdh_kat(
        secp256r1,
        "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8",
        "a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3",
        "ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536");

    ecdh_kat(
        secp256r1,
        "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d",
        "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed",
        "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4");

    ecdh_kat(
        secp256r1,
        "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf",
        "41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922",
        "1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328");

    ecdh_kat(
        secp256r1,
        "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef",
        "33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792",
        "f2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f");

    ecdh_kat(
        secp256r1,
        "3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190",
        "6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7",
        "40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05");

    ecdh_kat(
        secp256r1,
        "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8",
        "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb",
        "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229");

    ecdh_kat(
        secp256r1,
        "0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d",
        "94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9",
        "d8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a");

    ecdh_kat(
        secp256r1,
        "2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08",
        "e099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f",
        "d9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5");

    ecdh_kat(
        secp256r1,
        "77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848",
        "f75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658",
        "33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c");
    ecdh_kat(
        secp256r1,
        "42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e",
        "2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d",
        "62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e");

    ecdh_kat(
        secp256r1,
        "ceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b",
        "cd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb",
        "c3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4");

    ecdh_kat(
        secp256r1,
        "43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604",
        "15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471",
        "cdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77");

    ecdh_kat(
        secp256r1,
        "b2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903",
        "49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1",
        "8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924");

    ecdh_kat(
        secp256r1,
        "4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8",
        "19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c",
        "09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae");

    ecdh_kat(
        secp256r1,
        "4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147",
        "2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954",
        "6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0");

    ecdh_kat(
        secp256r1,
        "1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e",
        "a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767",
        "dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03");

    ecdh_kat(
        secp256r1,
        "dd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3",
        "a2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644",
        "563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a");

    ecdh_kat(
        secp256r1,
        "5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76",
        "ccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f",
        "e9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38");

    ecdh_kat(
        secp256r1,
        "b601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d",
        "c188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e",
        "bf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051");

    ecdh_kat(
        secp256r1,
        "fefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535",
        "317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6",
        "09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae");

    ecdh_kat(
        secp256r1,
        "334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce",
        "45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1",
        "5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321");

    ecdh_kat(
        secp256r1,
        "2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d",
        "a19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6",
        "e9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef");

    ecdh_kat(
        secp256r1,
        "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0",
        "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b",
        "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92");
#endif
  } else if (!strncmp("secp384r1", argv[1], 9)) {
    ecc_pointmul(secp384r1);
  } else if (!strncmp("secp521r1", argv[1], 9)) {
    ecc_pointmul(secp521r1);
  } else if (!strncmp("frp256v1", argv[1], 8)) {
#if defined(ECC_POINTMUL)
    ecc_pointmul(frp256v1);
#elif defined(ECDH)
    ecdh_kat(
        frp256v1,
        "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
        "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac");

    ecdh_kat(
        frp256v1,
        "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5",
        "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
        "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3");

    ecdh_kat(
        frp256v1,
        "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8",
        "a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3",
        "ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536");

    ecdh_kat(
        frp256v1,
        "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d",
        "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed",
        "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4");

    ecdh_kat(
        frp256v1,
        "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf",
        "41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922",
        "1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328");

    ecdh_kat(
        frp256v1,
        "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef",
        "33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792",
        "f2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f");

    ecdh_kat(
        frp256v1,
        "3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190",
        "6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7",
        "40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05");

    ecdh_kat(
        frp256v1,
        "d8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8",
        "a9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb",
        "f6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229");

    ecdh_kat(
        frp256v1,
        "0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d",
        "94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9",
        "d8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a");

    ecdh_kat(
        frp256v1,
        "2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08",
        "e099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f",
        "d9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5");

    ecdh_kat(
        frp256v1,
        "77c15dcf44610e41696bab758943eff1409333e4d5a11bbe72c8f6c395e9f848",
        "f75a5fe56bda34f3c1396296626ef012dc07e4825838778a645c8248cff01658",
        "33bbdf1b1772d8059df568b061f3f1122f28a8d819167c97be448e3dc3fb0c3c");
    ecdh_kat(
        frp256v1,
        "42a83b985011d12303db1a800f2610f74aa71cdf19c67d54ce6c9ed951e9093e",
        "2db4540d50230756158abf61d9835712b6486c74312183ccefcaef2797b7674d",
        "62f57f314e3f3495dc4e099012f5e0ba71770f9660a1eada54104cdfde77243e");

    ecdh_kat(
        frp256v1,
        "ceed35507b5c93ead5989119b9ba342cfe38e6e638ba6eea343a55475de2800b",
        "cd94fc9497e8990750309e9a8534fd114b0a6e54da89c4796101897041d14ecb",
        "c3def4b5fe04faee0a11932229fff563637bfdee0e79c6deeaf449f85401c5c4");

    ecdh_kat(
        frp256v1,
        "43e0e9d95af4dc36483cdd1968d2b7eeb8611fcce77f3a4e7d059ae43e509604",
        "15b9e467af4d290c417402e040426fe4cf236bae72baa392ed89780dfccdb471",
        "cdf4e9170fb904302b8fd93a820ba8cc7ed4efd3a6f2d6b05b80b2ff2aee4e77");

    ecdh_kat(
        frp256v1,
        "b2f3600df3368ef8a0bb85ab22f41fc0e5f4fdd54be8167a5c3cd4b08db04903",
        "49c503ba6c4fa605182e186b5e81113f075bc11dcfd51c932fb21e951eee2fa1",
        "8af706ff0922d87b3f0c5e4e31d8b259aeb260a9269643ed520a13bb25da5924");

    ecdh_kat(
        frp256v1,
        "4002534307f8b62a9bf67ff641ddc60fef593b17c3341239e95bdb3e579bfdc8",
        "19b38de39fdd2f70f7091631a4f75d1993740ba9429162c2a45312401636b29c",
        "09aed7232b28e060941741b6828bcdfa2bc49cc844f3773611504f82a390a5ae");

    ecdh_kat(
        frp256v1,
        "4dfa12defc60319021b681b3ff84a10a511958c850939ed45635934ba4979147",
        "2c91c61f33adfe9311c942fdbff6ba47020feff416b7bb63cec13faf9b099954",
        "6cab31b06419e5221fca014fb84ec870622a1b12bab5ae43682aa7ea73ea08d0");

    ecdh_kat(
        frp256v1,
        "1331f6d874a4ed3bc4a2c6e9c74331d3039796314beee3b7152fcdba5556304e",
        "a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767",
        "dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03");

    ecdh_kat(
        frp256v1,
        "dd5e9f70ae740073ca0204df60763fb6036c45709bf4a7bb4e671412fad65da3",
        "a2ef857a081f9d6eb206a81c4cf78a802bdf598ae380c8886ecd85fdc1ed7644",
        "563c4c20419f07bc17d0539fade1855e34839515b892c0f5d26561f97fa04d1a");

    ecdh_kat(
        frp256v1,
        "5ae026cfc060d55600717e55b8a12e116d1d0df34af831979057607c2d9c2f76",
        "ccd8a2d86bc92f2e01bce4d6922cf7fe1626aed044685e95e2eebd464505f01f",
        "e9ddd583a9635a667777d5b8a8f31b0f79eba12c75023410b54b8567dddc0f38");

    ecdh_kat(
        frp256v1,
        "b601ac425d5dbf9e1735c5e2d5bdb79ca98b3d5be4a2cfd6f2273f150e064d9d",
        "c188ffc8947f7301fb7b53e36746097c2134bf9cc981ba74b4e9c4361f595e4e",
        "bf7d2f2056e72421ef393f0c0f2b0e00130e3cac4abbcc00286168e85ec55051");

    ecdh_kat(
        frp256v1,
        "fefb1dda1845312b5fce6b81b2be205af2f3a274f5a212f66c0d9fc33d7ae535",
        "317e1020ff53fccef18bf47bb7f2dd7707fb7b7a7578e04f35b3beed222a0eb6",
        "09420ce5a19d77c6fe1ee587e6a49fbaf8f280e8df033d75403302e5a27db2ae");

    ecdh_kat(
        frp256v1,
        "334ae0c4693d23935a7e8e043ebbde21e168a7cba3fa507c9be41d7681e049ce",
        "45fb02b2ceb9d7c79d9c2fa93e9c7967c2fa4df5789f9640b24264b1e524fcb1",
        "5c6e8ecf1f7d3023893b7b1ca1e4d178972ee2a230757ddc564ffe37f5c5a321");

    ecdh_kat(
        frp256v1,
        "2c4bde40214fcc3bfc47d4cf434b629acbe9157f8fd0282540331de7942cf09d",
        "a19ef7bff98ada781842fbfc51a47aff39b5935a1c7d9625c8d323d511c92de6",
        "e9c184df75c955e02e02e400ffe45f78f339e1afe6d056fb3245f4700ce606ef");

    ecdh_kat(
        frp256v1,
        "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0",
        "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b",
        "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92");
#endif

  }

  EC_GROUP_free(frp256v1);
  EC_GROUP_free(secp521r1);
  EC_GROUP_free(secp384r1);
  EC_GROUP_free(secp256r1);
  EC_GROUP_free(secp224r1);
  EC_GROUP_free(secp192r1);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ERR_remove_thread_state(NULL);
  CRYPTO_mem_leaks_fp(stderr);

  return 0;
}
