//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE sha3_test

#include <iostream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/sha3.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::accumulators;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha3<224>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha3<256>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha3<384>::construction::type::digest_type)
BOOST_TEST_DONT_PRINT_LOG_VALUE(hashes::sha3<512>::construction::type::digest_type)

template<std::size_t Size>
class fixture {
public:
    accumulator_set<hashes::sha3<Size>> acc;
    typedef hashes::sha3<Size> hash_t;

    virtual ~fixture() {
    }
};

const char *test_data = "data/sha3.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    boost::property_tree::ptree string_data = root_data.get_child(child_name);

    return string_data;
}

BOOST_AUTO_TEST_SUITE(sha3_stream_processor_data_driven_test_suite)

BOOST_DATA_TEST_CASE(sha3_224_range_hash, string_data("data_224"), array_element) {
    std::string out = hash<hashes::sha3<224>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha3_256_range_hash, string_data("data_256"), array_element) {
    std::string out = hash<hashes::sha3<256>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha3_384_range_hash, string_data("data_384"), array_element) {
    std::string out = hash<hashes::sha3<384>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_DATA_TEST_CASE(sha3_512_range_hash, string_data("data_512"), array_element) {
    std::string out = hash<hashes::sha3<512>>(array_element.first);

    BOOST_CHECK_EQUAL(out, array_element.second.data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha3_stream_processor_test_suite)

/*BOOST_AUTO_TEST_CASE(sha3_224_shortmsg_bit1) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg5.pdf
    std::array<bool, 5> a = {1, 1, 0, 0, 1};
    hashes::sha3<224>::digest_type d = hashes<hashes::sha3<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("ffbad5da96bad71789330206dc6768ecaeb1b32dca6b3301489674ab", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_shortmsg_bit2) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_Msg30.pdf
    std::array<bool, 30> a = {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0};
    hashes::sha3<224>::digest_type d = hashes<hashes::sha3<224>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("d666a514cc9dba25ac1ba69ed3930460deaac9851b5f0baab007df3b", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(sha3_224_shortmsg_byte1) {
    // echo -n "a" | sha3sum
    std::array<char, 1> a = {'\x61'};
    hashes::sha3<224>::digest_type d = hash<hashes::sha3<224>>(a);

    BOOST_CHECK_EQUAL("9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_shortmsg_byte2) {
    // echo -n "abc" | sha3sum
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::sha3<224>::digest_type d = hash<hashes::sha3<224>>(a);

    BOOST_CHECK_EQUAL("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_shortmsg_byte3) {
    // echo -n "message digest" | sha3sum
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::sha3<224>::digest_type d = hash<hashes::sha3<224>>(a);

    BOOST_CHECK_EQUAL("18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8", std::to_string(d).data());
}

/*BOOST_AUTO_TEST_CASE(sha3_256_shortmsg_bit1) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg5.pdf
    std::array<bool, 5> a = {1, 1, 0, 0, 1};
    hashes::sha3<256>::digest_type d = hashes<hashes::sha3<256>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("7b0047cf5a456882363cbf0fb05322cf65f4b7059a46365e830132e3b5d957af", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_shortmsg_bit2) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg30.pdf
    std::array<bool, 30> a = {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0};
    hashes::sha3<256>::digest_type d = hashes<hashes::sha3<256>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("c8242fef409e5ae9d1f1c857ae4dc624b92b19809f62aa8c07411c54a078b1d0", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(sha3_256_shortmsg_byte1) {
    // echo -n "a" | sha3sum -a 256
    std::array<char, 1> a = {'\x61'};
    hashes::sha3<256>::digest_type d = hash<hashes::sha3<256>>(a);

    BOOST_CHECK_EQUAL("80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_shortmsg_byte2) {
    // echo -n "abc" | sha3sum -a 256
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::sha3<256>::digest_type d = hash<hashes::sha3<256>>(a);

    BOOST_CHECK_EQUAL("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_shortmsg_byte3) {
    // echo -n "message digest" | sha3sum -a 256
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::sha3<256>::digest_type d = hash<hashes::sha3<256>>(a);

    BOOST_CHECK_EQUAL("edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd", std::to_string(d).data());
}

/*BOOST_AUTO_TEST_CASE(sha3_384_shortmsg_bit1) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg5.pdf
    std::array<bool, 5> a = {1, 1, 0, 0, 1};
    hashes::sha3<384>::digest_type d = hashes<hashes::sha3<384>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("737c9b491885e9bf7428e792741a7bf8dca9653471c3e148473f2c236b6a0a64"
                      "55eb1dce9f779b4b6b237fef171b1c64", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_shortmsg_bit2) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_Msg30.pdf
    std::array<bool, 30> a = {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0};
    hashes::sha3<384>::digest_type d = hashes<hashes::sha3<384>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("955b4dd1be03261bd76f807a7efd432435c417362811b8a50c564e7ee9585e1a"
                      "c7626dde2fdc030f876196ea267f08c3", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(sha3_384_shortmsg_byte1) {
    // echo -n "a" | sha3sum -a 384
    std::array<char, 1> a = {'\x61'};
    hashes::sha3<384>::digest_type d = hash<hashes::sha3<384>>(a);

    BOOST_CHECK_EQUAL(
        "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7"
        "ea44f93ee1234aa88f61c91912a4ccd9",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_shortmsg_byte2) {
    // echo -n "abc" | sha3sum -a 384
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::sha3<384>::digest_type d = hash<hashes::sha3<384>>(a);

    BOOST_CHECK_EQUAL(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_shortmsg_byte3) {
    // echo -n "message digest" | sha3sum -a 384
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::sha3<384>::digest_type d = hash<hashes::sha3<384>>(a);

    BOOST_CHECK_EQUAL(
        "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe6627515"
        "13f19ad57e17d4b93ba1e484fc1980d5",
        std::to_string(d).data());
}

/*BOOST_AUTO_TEST_CASE(sha3_512_shortmsg_bit1) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg5.pdf
    std::array<bool, 5> a = {1, 1, 0, 0, 1};
    hashes::sha3<512>::digest_type d = hashes<hashes::sha3<512>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("a13e01494114c09800622a70288c432121ce70039d753cadd2e006e4d961cb27"
                      "544c1481e5814bdceb53be6733d5e099795e5e81918addb058e22a9f24883f37", std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_shortmsg_bit2) {
    //
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_Msg30.pdf
    std::array<bool, 30> a = {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0};
    hashes::sha3<512>::digest_type d = hashes<hashes::sha3<512>>(a);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(d).data());
#endif

    BOOST_CHECK_EQUAL("9834c05a11e1c5d3da9c740e1c106d9e590a0e530b6f6aaa7830525d075ca5db"
                      "1bd8a6aa981a28613ac334934a01823cd45f45e49b6d7e6917f2f16778067bab", std::to_string(d).data());
}*/

BOOST_AUTO_TEST_CASE(sha3_512_shortmsg_byte1) {
    // echo -n "a" | sha3sum -a 512
    std::array<char, 1> a = {'\x61'};
    hashes::sha3<512>::digest_type d = hash<hashes::sha3<512>>(a);

    BOOST_CHECK_EQUAL(
        "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa80"
        "3f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_shortmsg_byte2) {
    // echo -n "abc" | sha3sum -a 512
    std::array<char, 3> a = {'\x61', '\x62', '\x63'};
    hashes::sha3<512>::digest_type d = hash<hashes::sha3<512>>(a);

    BOOST_CHECK_EQUAL(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_shortmsg_byte3) {
    // echo -n "message digest" | sha3sum -a 512
    std::array<char, 14> a = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65',
                              '\x20', '\x64', '\x69', '\x67', '\x65', '\x73', '\x74'};
    hashes::sha3<512>::digest_type d = hash<hashes::sha3<512>>(a);

    BOOST_CHECK_EQUAL(
        "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141"
        "ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59",
        std::to_string(d).data());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(sha3_accumulator_test_suite)

BOOST_FIXTURE_TEST_CASE(sha3_224_accumulator1, fixture<224>) {
    // bit string {1, 1, 0, 0, 1}
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x1300000000000000);
    acc(m, accumulators::bits = 5);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("ffbad5da96bad71789330206dc6768ecaeb1b32dca6b3301489674ab", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_224_accumulator2, fixture<224>) {
    // bit string {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0}
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x53587B1900000000);
    acc(m, accumulators::bits = 30);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("d666a514cc9dba25ac1ba69ed3930460deaac9851b5f0baab007df3b", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_224_accumulator3, fixture<224>) {
    // echo -n "abc" | sha3sum
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_224_accumulator4, fixture<224>) {
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-224_1600.pdf
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3000102094000b8), UINT64_C(0x67283609c1251003)}};
    acc(m1, accumulators::bits = 16 * 64 + 8);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL("f434c78aa907e811d189dfe93223461f4fa0bcc28d5b445e70b24cc8", std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a300),
         UINT64_C(0x6a6b6c6d6e6f7071), UINT64_C(0x6b6c6d6e6f707172), UINT64_C(0x6c6d6e6f70717273),
         UINT64_C(0x6d6e6f7071727374), UINT64_C(0x6e6f707172737475), UINT64_C(0x0000000000000000),
         UINT64_C(0x0000000000000000), UINT64_C(0xc5000102094000b8), UINT64_C(0x67283609c1251003)}};

    acc(m2, accumulators::bits = 9 * 64 - 8);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_256_accumulator1, fixture<256>) {
    // bit string {1, 1, 0, 0, 1}
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x1300000000000000);
    acc(m, accumulators::bits = 5);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("7b0047cf5a456882363cbf0fb05322cf65f4b7059a46365e830132e3b5d957af", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_256_accumulator2, fixture<256>) {
    // echo -n "abc" | sha3sum -a 256
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_256_accumulator3, fixture<256>) {
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_1600.pdf
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3000102094000b8)}};
    acc(m1, accumulators::bits = 16 * 64 + 8);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL("7e23024b73e352998831831553db3c2867858bb4889d53a3be1af099dd79c0e1", std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a300),
         UINT64_C(0x6a6b6c6d6e6f7071), UINT64_C(0x6b6c6d6e6f707172), UINT64_C(0x6c6d6e6f70717273),
         UINT64_C(0x6d6e6f7071727374), UINT64_C(0x6e6f707172737475), UINT64_C(0x0000000000000000),
         UINT64_C(0x0000000000000000), UINT64_C(0xc5000102094000b8)}};

    acc(m2, accumulators::bits = 9 * 64 - 8);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787", std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_384_accumulator1, fixture<384>) {
    // bit string {1, 1, 0, 0, 1}
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x1300000000000000);
    acc(m, accumulators::bits = 5);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "737c9b491885e9bf7428e792741a7bf8dca9653471c3e148473f2c236b6a0a64"
        "55eb1dce9f779b4b6b237fef171b1c64",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_384_accumulator2, fixture<384>) {
    // echo -n "abc" | sha3sum -a 384
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_384_accumulator3, fixture<384>) {
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-384_1600.pdf
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3000102030405)}};
    acc(m1, accumulators::bits = 12 * 64 + 16);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "c64ede18dc59558ee999ee4c10e3b00566b63bd8b5417b797bcd0efa5c71db6d"
        "3107b481933b6fe4be882e3822bd4578",
        std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a37374)}};

    acc(m2, accumulators::bits = 12 * 64 + 48);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd"
        "76197a31fd55ee989f2d7050dd473e8f",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_512_accumulator1, fixture<512>) {
    // bit string {1, 1, 0, 0, 1}
    hash_t::construction::type::block_type m = {{}};
    m[0] = UINT64_C(0x1300000000000000);
    acc(m, accumulators::bits = 5);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "a13e01494114c09800622a70288c432121ce70039d753cadd2e006e4d961cb27"
        "544c1481e5814bdceb53be6733d5e099795e5e81918addb058e22a9f24883f37",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_512_accumulator2, fixture<512>) {
    // echo -n "abc" | sha3sum -a 512
    hash_t::construction::type::block_type m = {{}};

    m[0] = UINT64_C(0x6162630000000000);
    acc(m, accumulators::bits = 24);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        std::to_string(s).data());
}

BOOST_FIXTURE_TEST_CASE(sha3_512_accumulator3, fixture<512>) {
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-512_1600.pdf
    hash_t::construction::type::block_type m1 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3)}};
    acc(m1, accumulators::bits = 9 * 64);

    hash_t::digest_type s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "d24ce75b87c7be36e3fedbaa285f563d3efcc13663f5eb2fdd0c60033dab04e8"
        "94d343b3971bc0c9ba30e0dde18106cbaaa955c8c3c0bf1ec3490aafcae15788",
        std::to_string(s).data());

    hash_t::construction::type::block_type m2 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3ff)}};

    acc(m2, accumulators::bits = 8 * 64 + 56);

    s = extract::hash<hash_t>(acc);

    BOOST_CHECK_EQUAL(
        "1b307700232bb68bb21801114085485d7c5f1c1e77eb143fbea9572d2845c244"
        "8a9349de9c34c870206e76cc6aab80365139828ca190d351fc70b83bf893076a",
        std::to_string(s).data());

    hash_t::construction::type::block_type m3 = {
        {UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa3a3a3a3a3a3a3a3),
         UINT64_C(0xa3a3a3a3a3a3a3a3), UINT64_C(0xa300901278231349), UINT64_C(0x5867344857584354)}};

    acc(m3, accumulators::bits = 7 * 64 + 8);

    s = extract::hash<hash_t>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8"
        "1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_preprocessor1) {
    accumulator_set<hashes::sha3<224>> acc;
    hashes::sha3<224>::digest_type s = extract::hash<hashes::sha3<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_preprocessor2) {
    accumulator_set<hashes::sha3<224>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::sha3<224>::digest_type s = extract::hash<hashes::sha3<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_224_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | sha3sum
    accumulator_set<hashes::sha3<224>> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);

    hashes::sha3<224>::digest_type s = extract::hash<hashes::sha3<224>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_preprocessor1) {
    accumulator_set<hashes::sha3<256>> acc;
    hashes::sha3<256>::digest_type s = extract::hash<hashes::sha3<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_preprocessor2) {
    accumulator_set<hashes::sha3<256>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::sha3<256>::digest_type s = extract::hash<hashes::sha3<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_256_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | sha3sum -a 256
    accumulator_set<hashes::sha3<256>> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);

    hashes::sha3<256>::digest_type s = extract::hash<hashes::sha3<256>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1", std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_preprocessor1) {
    accumulator_set<hashes::sha3<384>> acc;
    hashes::sha3<384>::digest_type s = extract::hash<hashes::sha3<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_preprocessor2) {
    accumulator_set<hashes::sha3<384>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::sha3<384>::digest_type s = extract::hash<hashes::sha3<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_384_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | sha3sum -a 384
    accumulator_set<hashes::sha3<384>> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);

    hashes::sha3<384>::digest_type s = extract::hash<hashes::sha3<384>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e7684"
        "7aa0774ddb90a842190d2c558b4b8340",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_preprocessor1) {
    accumulator_set<hashes::sha3<512>> acc;
    hashes::sha3<512>::digest_type s = extract::hash<hashes::sha3<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_preprocessor2) {
    accumulator_set<hashes::sha3<512>> acc;

    acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6200000000000000), accumulators::bits = 8);
    acc(UINT64_C(0x6300000000000000), accumulators::bits = 8);

    hashes::sha3<512>::digest_type s = extract::hash<hashes::sha3<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_CASE(sha3_512_preprocessor3) {
    // perl -e 'for (1..1000000) { print "a"; }' | sha3sum -a 512
    accumulator_set<hashes::sha3<512>> acc;

    for (unsigned i = 0; i != 1000000; ++i)
        acc(UINT64_C(0x6100000000000000), accumulators::bits = 8);

    hashes::sha3<512>::digest_type s = extract::hash<hashes::sha3<512>>(acc);

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
    std::printf("%s\n", std::to_string(s).data());
#endif

    BOOST_CHECK_EQUAL(
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859"
        "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
        std::to_string(s).data());
}

BOOST_AUTO_TEST_SUITE_END()