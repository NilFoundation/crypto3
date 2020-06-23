//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/threefish.hpp>


using namespace nil::crypto3;

template<std::size_t Size>
class fixture {
public:
    typedef block::threefish<Size> cipher_type;
    typedef typename cipher_type::key_type key_type;
    typedef typename cipher_type::tweak_type tweak_type;
    typedef typename cipher_type::block_type block_type;

    typedef digest<Size> digest_type;
};

BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<256>::digest_type)

BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<256>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<512>::block_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(fixture<1024>::block_type)

BOOST_AUTO_TEST_SUITE(threefish_test_suite)

BOOST_FIXTURE_TEST_CASE(threefish_256_encrypt2, fixture<256>) {
    tweak_type t = {{UINT64_C(0x0706050403020100), UINT64_C(0x0F0E0D0C0B0A0908)}};
    key_type k = {{UINT64_C(0x1716151413121110), UINT64_C(0x1F1E1D1C1B1A1918), UINT64_C(0x2726252423222120),
                   UINT64_C(0x2F2E2D2C2B2A2928)}};
    cipher_type c(k, t);
    block_type pt = {{UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(0xE8E9EAEBECEDEEEF),
                      UINT64_C(0xE0E1E2E3E4E5E6E7)}};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
    block_type ect = {{UINT64_C(0x1195ED1B648F9B1E), UINT64_C(0xA1D7C357DF404FBE), UINT64_C(0x13F77ADD8E7142BC),
                       UINT64_C(0xF820A9B2524C3D9B)}};
#else
    block_type ect = {{UINT64_C(0xD5DB258C5003E2CA), UINT64_C(0x697BDA64B7B1E9D6), UINT64_C(0x95FBB82D65D41C2E),
                       UINT64_C(0x8EF81E6E74516247)}};
#endif

    block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << to_digest<cipher_type>(ct) << std::endl;
#endif

    BOOST_CHECK_EQUAL(ct, ect);
}

BOOST_FIXTURE_TEST_CASE(threefish_512_encrypt2, fixture<512>) {
    tweak_type t = {{UINT64_C(0x0706050403020100), UINT64_C(0x0F0E0D0C0B0A0908)}};
    key_type k = {{UINT64_C(0x1716151413121110), UINT64_C(0x1F1E1D1C1B1A1918), UINT64_C(0x2726252423222120),
                   UINT64_C(0x2F2E2D2C2B2A2928), UINT64_C(0x3736353433323130), UINT64_C(0x3F3E3D3C3B3A3938),
                   UINT64_C(0x4746454443424140), UINT64_C(0x4F4E4D4C4B4A4948)}};
    cipher_type c(k, t);
    block_type pt = {{UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(0xE8E9EAEBECEDEEEF),
                      UINT64_C(0xE0E1E2E3E4E5E6E7), UINT64_C(0xD8D9DADBDCDDDEDF), UINT64_C(0xD0D1D2D3D4D5D6D7),
                      UINT64_C(0xC8C9CACBCCCDCECF), UINT64_C(0xC0C1C2C3C4C5C6C7)}};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
    block_type ect = {{UINT64_C(0x3B1DE51022E19A86), UINT64_C(0x0D40CB2A9F393607), UINT64_C(0x1D2FE6130B6030E2),
                       UINT64_C(0x81D23262146A59F7), UINT64_C(0x9A1B57657A12BFDF), UINT64_C(0x94836719C7068979),
                       UINT64_C(0xF283FD3851990DC5), UINT64_C(0xF0D250C33B4AA5BF)}};
#else
    block_type ect = {{UINT64_C(0x5D6EF7FC78E90D95), UINT64_C(0xF6E6216619FDADAD), UINT64_C(0x19C009C55B0CC7D5),
                       UINT64_C(0xA0281898E0A4F8DD), UINT64_C(0x841567AB57477CBD), UINT64_C(0x1836BC7C0D6C128D),
                       UINT64_C(0xA10377C64EDD1AE8), UINT64_C(0xAE51F0177E206DF2)}};
#endif
    block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << to_digest<cipher_type>(ct) std::endl;
#endif

    BOOST_CHECK_EQUAL(ct, ect);
}

BOOST_FIXTURE_TEST_CASE(threefish_1024_encrypt2, fixture<1024>) {
    tweak_type t = {{
        UINT64_C(0x0706050403020100),
        UINT64_C(0x0F0E0D0C0B0A0908),
    }};
    key_type k = {{
        UINT64_C(0x1716151413121110),
        UINT64_C(0x1F1E1D1C1B1A1918),
        UINT64_C(0x2726252423222120),
        UINT64_C(0x2F2E2D2C2B2A2928),
        UINT64_C(0x3736353433323130),
        UINT64_C(0x3F3E3D3C3B3A3938),
        UINT64_C(0x4746454443424140),
        UINT64_C(0x4F4E4D4C4B4A4948),
        UINT64_C(0x5756555453525150),
        UINT64_C(0x5F5E5D5C5B5A5958),
        UINT64_C(0x6766656463626160),
        UINT64_C(0x6F6E6D6C6B6A6968),
        UINT64_C(0x7776757473727170),
        UINT64_C(0x7F7E7D7C7B7A7978),
        UINT64_C(0x8786858483828180),
        UINT64_C(0x8F8E8D8C8B8A8988),
    }};
    cipher_type c(k, t);
    block_type pt = {{UINT64_C(0xF8F9FAFBFCFDFEFF), UINT64_C(0xF0F1F2F3F4F5F6F7), UINT64_C(0xE8E9EAEBECEDEEEF),
                      UINT64_C(0xE0E1E2E3E4E5E6E7), UINT64_C(0xD8D9DADBDCDDDEDF), UINT64_C(0xD0D1D2D3D4D5D6D7),
                      UINT64_C(0xC8C9CACBCCCDCECF), UINT64_C(0xC0C1C2C3C4C5C6C7), UINT64_C(0xB8B9BABBBCBDBEBF),
                      UINT64_C(0xB0B1B2B3B4B5B6B7), UINT64_C(0xA8A9AAABACADAEAF), UINT64_C(0xA0A1A2A3A4A5A6A7),
                      UINT64_C(0x98999A9B9C9D9E9F), UINT64_C(0x9091929394959697), UINT64_C(0x88898A8B8C8D8E8F),
                      UINT64_C(0x8081828384858687)}};
#ifdef CRYPTO3_HASH_THREEFISH_OLD_ROTATION_CONSTANTS
    block_type ect = {{UINT64_C(0x4243AA25316BE644), UINT64_C(0x1C1010C3F4BEAD61), UINT64_C(0x3231B47252181DEF),
                       UINT64_C(0x51282B69757EE6D6), UINT64_C(0xC6D6D3DFF8ACE3A7), UINT64_C(0x7E280D152427EADF),
                       UINT64_C(0xFA71E927FFAB2B8C), UINT64_C(0xBFF281E11B7863C1), UINT64_C(0xF89E256248B82A57),
                       UINT64_C(0x8F121DA6778A62FA), UINT64_C(0xFE928551BD17152F), UINT64_C(0xDA8A840D67FF8293),
                       UINT64_C(0xC6C236CFDC8215B3), UINT64_C(0x3F85A234AE3A1507), UINT64_C(0xCC03C962F44CC1F0),
                       UINT64_C(0xB1040CE54A736028)}};
#else
    block_type ect = {{UINT64_C(0x2464AD5AB185DC77), UINT64_C(0xE04DC8BFD571E31C), UINT64_C(0x9CE6A73480A1915A),
                       UINT64_C(0x3608792385E3FE33), UINT64_C(0x32CD1A7B3E1968F5), UINT64_C(0x2343B04DFCF1FF69),
                       UINT64_C(0xB94C44202614975E), UINT64_C(0xA51A8C5A489F0737), UINT64_C(0x8B01DD5EF172F8DF),
                       UINT64_C(0xC6527AFA44CD0CEC), UINT64_C(0xA976533327140A77), UINT64_C(0x1DB3AE193971D14E),
                       UINT64_C(0xCA4A2858E912B0B7), UINT64_C(0x7665A8A50E6B22E5), UINT64_C(0x8127345A2CF99C4A),
                       UINT64_C(0x9EF278F6CC3E417E)}};
#endif
    block_type ct = c.encrypt(pt);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::cout << to_digest<cipher_type>(ct) std::endl;
#endif

    BOOST_CHECK_EQUAL(ct, ect);
}

BOOST_AUTO_TEST_CASE(threefish_1) {

    std::vector<char> input = {'\xb1', '\xa2', '\xbb', '\xc6', '\xef', '\x60', '\x25', '\xbc', 
    '\x40', '\xeb', '\x38', '\x22', '\x16', '\x1f', '\x36', '\xe3', '\x75', '\xd1', '\xbb', 
    '\x0a', '\xee', '\x31', '\x86', '\xfb', '\xd1', '\x9e', '\x47', '\xc5', '\xd4', '\x79', 
    '\x94', '\x7b', '\x7b', '\xc2', '\xf8', '\x58', '\x6e', '\x35', '\xf0', '\xcf', '\xf7', 
    '\xe7', '\xf0', '\x30', '\x84', '\xb0', '\xb7', '\xb1', '\xf1', '\xab', '\x39', '\x61', 
    '\xa5', '\x80', '\xa3', '\xe9', '\x7e', '\xb4', '\x1e', '\xa1', '\x4a', '\x6d', '\x7b', '\xbe'};
    std::vector<char> key = {'\xf1', '\x3c', '\xa0', '\x67', '\x60', '\xdd', '\x9b', '\xbe', 
    '\xab', '\x87', '\xb6', '\xc5', '\x6f', '\x3b', '\xbb', '\xdb', '\xe9', '\xd0', '\x8a', 
    '\x77', '\x97', '\x8b', '\x94', '\x2a', '\xc0', '\x2d', '\x47', '\x1d', '\xc1', '\x02', 
    '\x68', '\xf2', '\x26', '\x1c', '\x3d', '\x43', '\x30', '\xd6', '\xca', '\x34', '\x1f', 
    '\x4b', '\xd4', '\x11', '\x5d', '\xee', '\x16', '\xa2', '\x1d', '\xcd', '\xa2', '\xa3', 
    '\x4a', '\x0a', '\x76', '\xfb', '\xa9', '\x76', '\x17', '\x4e', '\x4c', '\xf1', '\xe3', '\x06'};

    std::string out = encrypt<block::threefish<512>>(input, key);
    
    BOOST_CHECK_EQUAL(out, "1bec82cba1357566b34e1cf1fbf123a141c8f4089f6e4ce3209aea10095aec93c900d068bdc7f7a2dd58513c11dec956b93169b1c4f24cede31a265de83e36b4");
}

BOOST_AUTO_TEST_SUITE_END()