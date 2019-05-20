//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE threefish_512_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>

#include <nil/crypto3/block/threefish.hpp>

#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/hex.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;

template<typename cipher_type, typename state_type>
typename cipher_type::template stream_cipher<8>::type::digest_type to_digest(state_type state) {
    typename cipher_type::template stream_cipher<8>::type::digest_type d;
    pack_n<stream_endian::little_octet_big_bit, cipher_type::word_bits, octet_bits>(state.begin(),
            cipher_type::block_bits / cipher_type::word_bits, std::back_inserter(d),
            cipher_type::block_bits * octet_bits / cipher_type::word_bits);
    return d;
}

template<std::size_t Size>
class fixture {
public:
    typedef threefish<Size> cipher_type;
    typedef typename cipher_type::key_type key_type;
    typedef typename cipher_type::tweak_type tweak_type;
    typedef typename cipher_type::block_type block_type;

    typedef block::digest<Size> digest_type;
};

BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<256>::digest_type)

BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<256>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<512>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<1024>::block_type)

BOOST_AUTO_TEST_SUITE(threefish_test_suite)

    BOOST_FIXTURE_TEST_CASE(threefish_256_encrypt1, fixture<256>) {
        // All-zero key, tweak, and plaintext
        cipher_type cipher((key_type()));
        block_type ciphertext = cipher.encrypt(block_type());
        digest_type d = to_digest<cipher_type>(ciphertext);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << d << std::endl;
#endif

        std::string string_digest = decode<codec::hex>(d);
#ifdef CRYPTO3_BLOCK_THREEFISH_OLD_ROTATION_CONSTANTS
        BOOST_CHECK_EQUAL(string_digest, "e39756f9f3b6cf3ff91d2bc3d324ce618574ea1623b2367f88382e2a93afa858");
#else
        BOOST_CHECK_EQUAL(string_digest, "eb373aaeb6f28d3f6343799c778aadae98c87a2888b43842b06295c7d76af54b");
#endif
    }

    BOOST_FIXTURE_TEST_CASE(threefish_256_encrypt2, fixture<256>) {
        tweak_type t = {{UINT64_C(0x0706050403020100), UINT64_C(0x0F0E0D0C0B0A0908)}};
        key_type k = {{
                              UINT64_C(0x1716151413121110), UINT64_C(0x1F1E1D1C1B1A1918), UINT64_C(
                                                                                                  0x2726252423222120), UINT64_C(
                                                                                                                               0x2F2E2D2C2B2A2928)
                      }};
        cipher_type c(k, t);
        block_type pt = {{
                                 UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(
                                                                                                     0xE8E9EAEBECEDEEEF), UINT64_C(
                                                                                                                                  0xE0E1E2E3E4E5E6E7)
                         }};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
        block_type ect = {{UINT64_C(0x1195ED1B648F9B1E), UINT64_C(0xA1D7C357DF404FBE),
                        UINT64_C(0x13F77ADD8E7142BC), UINT64_C(0xF820A9B2524C3D9B)}};
#else
        block_type ect = {{
                                  UINT64_C(0xD5DB258C5003E2CA), UINT64_C(0x697BDA64B7B1E9D6), UINT64_C(
                                                                                                      0x95FBB82D65D41C2E), UINT64_C(
                                                                                                                                   0x8EF81E6E74516247)
                          }};
#endif

        block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << to_digest<cipher_type>(ct) << std::endl;
#endif

        BOOST_CHECK_EQUAL(ct, ect);
    }

    BOOST_FIXTURE_TEST_CASE(threefish_512_encrypt1, fixture<512>) {
        // All-zero key, tweak, and plaintext
        cipher_type cipher((key_type()));
        block_type ciphertext = cipher.encrypt(block_type());
        digest_type d = to_digest<cipher_type>(ciphertext);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << d std::endl;
#endif

        std::string string_digest = decode<decoder::hex, std::string>(d);
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
        BOOST_CHECK_EQUAL(string_digest, "408be942494492eab19daa3e96ad19aedfc41f4e55f8a2626c1e46d54547a713"
                       "d43b21f0de1a10881ed5c4adefdad1c4172cd768c8fc28d0dde9df018042fe3e");
#else
        BOOST_CHECK_EQUAL(string_digest, "54c48fea2dac72222c0380d1a1a9f7684d47bd90fc491724dc599e1824b6b30a"
                                         "e22db97e841482db209c0e6974c2111ad6c691984919c11f987fc2d132379fb4");
#endif
    }

    BOOST_FIXTURE_TEST_CASE(threefish_512_encrypt2, fixture<512>) {
        tweak_type t = {{UINT64_C(0x0706050403020100), UINT64_C(0x0F0E0D0C0B0A0908)}};
        key_type k = {{
                              UINT64_C(0x1716151413121110), UINT64_C(0x1F1E1D1C1B1A1918), UINT64_C(
                                                                                                  0x2726252423222120), UINT64_C(
                                                                                                                               0x2F2E2D2C2B2A2928), UINT64_C(
                                                                                                                                                            0x3736353433323130), UINT64_C(
                                                                                                                                                                                         0x3F3E3D3C3B3A3938), UINT64_C(
                                                                                                                                                                                                                      0x4746454443424140), UINT64_C(
                                                                                                                                                                                                                                                   0x4F4E4D4C4B4A4948)
                      }};
        cipher_type c(k, t);
        block_type pt = {{
                                 UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(
                                                                                                     0xE8E9EAEBECEDEEEF), UINT64_C(
                                                                                                                                  0xE0E1E2E3E4E5E6E7), UINT64_C(
                                                                                                                                                               0xD8D9DADBDCDDDEDF), UINT64_C(
                                                                                                                                                                                            0xD0D1D2D3D4D5D6D7), UINT64_C(
                                                                                                                                                                                                                         0xC8C9CACBCCCDCECF), UINT64_C(
                                                                                                                                                                                                                                                      0xC0C1C2C3C4C5C6C7)
                         }};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
        block_type ect = {{UINT64_C(0x3B1DE51022E19A86), UINT64_C(0x0D40CB2A9F393607),
                                UINT64_C(0x1D2FE6130B6030E2), UINT64_C(0x81D23262146A59F7),
                                UINT64_C(0x9A1B57657A12BFDF), UINT64_C(0x94836719C7068979),
                                UINT64_C(0xF283FD3851990DC5), UINT64_C(0xF0D250C33B4AA5BF)}};
#else
        block_type ect = {{
                                  UINT64_C(0x5D6EF7FC78E90D95), UINT64_C(0xF6E6216619FDADAD), UINT64_C(
                                                                                                      0x19C009C55B0CC7D5), UINT64_C(
                                                                                                                                   0xA0281898E0A4F8DD), UINT64_C(
                                                                                                                                                                0x841567AB57477CBD), UINT64_C(
                                                                                                                                                                                             0x1836BC7C0D6C128D), UINT64_C(
                                                                                                                                                                                                                          0xA10377C64EDD1AE8), UINT64_C(
                                                                                                                                                                                                                                                       0xAE51F0177E206DF2)
                          }};
#endif
        block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << to_digest<cipher_type>(ct) std::endl;
#endif

        BOOST_CHECK_EQUAL(ct, ect);
    }

    BOOST_FIXTURE_TEST_CASE(threefish_1024_encrypt1, fixture<1024>) {
        // All-zero key, tweak, and plaintext
        cipher_type cipher((key_type()));
        block_type ciphertext = cipher.encrypt(block_type());
        digest_type d = to_digest<cipher_type>(ciphertext);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << d std::endl;
#endif

        std::string string_digest = decode<decoder::hex, std::string>(d);
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
        BOOST_CHECK_EQUAL(string_digest, "43cf2a34cb1668e38c2e19ea1757d6b31ac6dead02fea99459d8a0331bdc7273"
                       "a1f7e9495d60402d1f8b43e48a5ac4f9d9d30965835e07f5455b87f963fdbca6"
                       "df66b4446b91ffdd27634573f6e0e4c19633cf80da8fe11b890bcf639ac67b34"
                       "7f87c5daa1acc1b8cd0303f4a9168c0b9b7b78baa6fc68db2cbd3337b8519170");
#else
        BOOST_CHECK_EQUAL(string_digest, "71bdc133e22bdc347d4eb02d9a7535f82de8d4c32622e0fd492083aace875edc"
                                         "6114e11fd928665e3a2947f2e92897d2f62a2afbb98d20a9e2a5ddfc6cdad498"
                                         "644874786afe373b7853672a6da106725e946b45d48ed270ed4843f1a5ac7a23"
                                         "97cc46f04d3736d8536612823db0ac1ffaa29e6fcc6eab4ff3f36cfaec59468a");
#endif
    }

    BOOST_FIXTURE_TEST_CASE(threefish_1024_encrypt2, fixture<1024>) {
        tweak_type t = {{UINT64_C(0x0706050403020100), UINT64_C(0x0F0E0D0C0B0A0908),}};
        key_type k = {{
                              UINT64_C(0x1716151413121110), UINT64_C(0x1F1E1D1C1B1A1918), UINT64_C(
                                                                                                  0x2726252423222120), UINT64_C(
                                                                                                                               0x2F2E2D2C2B2A2928), UINT64_C(
                                                                                                                                                            0x3736353433323130), UINT64_C(
                                                                                                                                                                                         0x3F3E3D3C3B3A3938), UINT64_C(
                                                                                                                                                                                                                      0x4746454443424140), UINT64_C(
                                                                                                                                                                                                                                                   0x4F4E4D4C4B4A4948), UINT64_C(
                                                                                                                                                                                                                                                                                0x5756555453525150), UINT64_C(
                                                                                                                                                                                                                                                                                                             0x5F5E5D5C5B5A5958), UINT64_C(
                                                                                                                                                                                                                                                                                                                                          0x6766656463626160), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                       0x6F6E6D6C6B6A6968), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                    0x7776757473727170), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                 0x7F7E7D7C7B7A7978), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                              0x8786858483828180), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           0x8F8E8D8C8B8A8988),
                      }};
        cipher_type c(k, t);
        block_type pt = {{
                                 UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(
                                                                                                     0xE8E9EAEBECEDEEEF), UINT64_C(
                                                                                                                                  0xE0E1E2E3E4E5E6E7), UINT64_C(
                                                                                                                                                               0xD8D9DADBDCDDDEDF), UINT64_C(
                                                                                                                                                                                            0xD0D1D2D3D4D5D6D7), UINT64_C(
                                                                                                                                                                                                                         0xC8C9CACBCCCDCECF), UINT64_C(
                                                                                                                                                                                                                                                      0xC0C1C2C3C4C5C6C7), UINT64_C(
                                                                                                                                                                                                                                                                                   0xB8B9BABBBCBDBEBF), UINT64_C(
                                                                                                                                                                                                                                                                                                                0xB0B1B2B3B4B5B6B7), UINT64_C(
                                                                                                                                                                                                                                                                                                                                             0xA8A9AAABACADAEAF), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                          0xA0A1A2A3A4A5A6A7), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                       0x98999A9B9C9D9E9F), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                    0x9091929394959697), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                 0x88898A8B8C8D8E8F), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              0x8081828384858687)
                         }};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
        block_type ect = {{UINT64_C(0x4243AA25316BE644), UINT64_C(0x1C1010C3F4BEAD61),
                          UINT64_C(0x3231B47252181DEF), UINT64_C(0x51282B69757EE6D6),
                          UINT64_C(0xC6D6D3DFF8ACE3A7), UINT64_C(0x7E280D152427EADF),
                          UINT64_C(0xFA71E927FFAB2B8C), UINT64_C(0xBFF281E11B7863C1),
                          UINT64_C(0xF89E256248B82A57), UINT64_C(0x8F121DA6778A62FA),
                          UINT64_C(0xFE928551BD17152F), UINT64_C(0xDA8A840D67FF8293),
                          UINT64_C(0xC6C236CFDC8215B3), UINT64_C(0x3F85A234AE3A1507),
                          UINT64_C(0xCC03C962F44CC1F0), UINT64_C(0xB1040CE54A736028)}};
#else
        block_type ect = {{
                                  UINT64_C(0x2464AD5AB185DC77), UINT64_C(0xE04DC8BFD571E31C), UINT64_C(
                                                                                                      0x9CE6A73480A1915A), UINT64_C(
                                                                                                                                   0x3608792385E3FE33), UINT64_C(
                                                                                                                                                                0x32CD1A7B3E1968F5), UINT64_C(
                                                                                                                                                                                             0x2343B04DFCF1FF69), UINT64_C(
                                                                                                                                                                                                                          0xB94C44202614975E), UINT64_C(
                                                                                                                                                                                                                                                       0xA51A8C5A489F0737), UINT64_C(
                                                                                                                                                                                                                                                                                    0x8B01DD5EF172F8DF), UINT64_C(
                                                                                                                                                                                                                                                                                                                 0xC6527AFA44CD0CEC), UINT64_C(
                                                                                                                                                                                                                                                                                                                                              0xA976533327140A77), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                           0x1DB3AE193971D14E), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                        0xCA4A2858E912B0B7), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                     0x7665A8A50E6B22E5), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0x8127345A2CF99C4A), UINT64_C(
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               0x9EF278F6CC3E417E)
                          }};
#endif
        block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
        std::cout << to_digest<cipher_type>(ct) std::endl;
#endif

        BOOST_CHECK_EQUAL(ct, ect);
    }

BOOST_AUTO_TEST_SUITE_END()