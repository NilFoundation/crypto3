//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE rijndael_cipher_test

#include <iostream>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/foreach.hpp>
#include <boost/assert.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/rijndael.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::block;
using namespace nil::crypto3::detail;

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

class byte_string {
    typedef std::vector<unsigned char> vec_type;

    vec_type s_;

public:
    typedef vec_type::size_type size_type;
    typedef vec_type::value_type value_type;
    typedef vec_type::pointer pointer;
    typedef vec_type::const_pointer const_pointer;
    typedef vec_type::reference reference;
    typedef vec_type::const_reference const_reference;
    typedef vec_type::iterator iterator;
    typedef vec_type::const_iterator const_iterator;

    explicit byte_string(size_type n, const value_type &value = value_type()) : s_(n, value) {
    }

    template<typename InputIterator>
    byte_string(InputIterator first, InputIterator last) : s_(first, last) {
    }

    byte_string(const std::string &src) {
        assert(!(src.size() % 2));
        // const unsigned char* src = static_cast<const unsigned char*>(vsrc);
        s_.resize(src.size() / 2);
        unsigned int j = 0;
        for (unsigned int i = 0; i < src.size();) {
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] = 16 * (src[i] - '0');
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] = 16 * (src[i] - 'a' + 10);
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 16 * (src[i] - 'A' + 10);
            }
            ++i;
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] += src[i] - '0';
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] += src[i] - 'a' + 10;
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 16 * (src[i] - 'A' + 10);
            }
            ++i;
            ++j;
        }

        /*for (size_type i = 0; i < len;)
        {
          value_type x;
          if (src[i] >= '0' && src[i] <= '9')
            x = 16 * (src[i] - '0');
          else if (src[i] >= 'a' && src[i] <= 'f')
            x = 16 * (src[i] - 'a' + 10);
          ++i;
          if (src[i] >= '0' && src[i] <= '9')
            x += src[i] - '0';
          else if (src[i] >= 'a' && src[i] <= 'f')
            x += src[i] - 'a' + 10;
          s_.push_back(x);
          ++i;
        }*/
    }

    byte_string(const byte_string &copy) : s_(copy.s_) {
    }

    size_type size() const {
        return s_.size();
    }

    pointer data() {
        return &s_[0];
    }

    const_pointer data() const {
        return &s_[0];
    }

    reference operator[](size_type i) {
        return s_[i];
    }

    const_reference operator[](size_type i) const {
        return s_[i];
    }

    void reserve(size_type n) {
        s_.reserve(n);
    }

    void resize(size_type n, value_type c = value_type()) {
        s_.resize(n, c);
    }

    iterator begin() {
        return s_.begin();
    }

    const_iterator begin() const {
        return s_.begin();
    }

    iterator end() {
        return s_.end();
    }

    const_iterator end() const {
        return s_.end();
    }

    iterator erase(iterator loc) {
        return s_.erase(loc);
    }

    iterator erase(iterator first, iterator last) {
        return s_.erase(first, last);
    }

    friend bool operator==(const byte_string &, const byte_string &);

    friend bool operator!=(const byte_string &, const byte_string &);

    byte_string &operator+=(const byte_string &rhs) {
        s_.insert(s_.end(), rhs.s_.begin(), rhs.s_.end());
        return *this;
    }
};

template<typename charT, class traits>
std::basic_ostream<charT, traits> &operator<<(std::basic_ostream<charT, traits> &out, const byte_string &s) {
    byte_string::size_type bufsize = s.size() * 2 + 1;
    char buf[bufsize];
    for (byte_string::size_type i = 0; i < s.size(); ++i) {
        std::sprintf(buf + i * 2, "%02x", s[i]);
    }
    buf[bufsize - 1] = '\0';
    out << buf;
    return out;
}

inline bool operator==(const byte_string &lhs, const byte_string &rhs) {
    return lhs.s_ == rhs.s_;
}

inline bool operator!=(const byte_string &lhs, const byte_string &rhs) {
    return lhs.s_ != rhs.s_;
}

const char *test_data = "data/rijndael.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    return root_data.get_child(child_name);
}

BOOST_AUTO_TEST_SUITE(rijndael_stream_processor_data_driven_test_suite)

BOOST_AUTO_TEST_CASE(rijndael_128_128_1) {

    std::vector<char> input = {'\x00', '\x11', '\x22', '\x33', '\x44', '\x55', '\x66', '\x77',
                               '\x88', '\x99', '\xaa', '\xbb', '\xcc', '\xdd', '\xee', '\xff'};
    std::vector<char> key = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                             '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f'};

    std::string out = encrypt<block::rijndael<128, 128>>(input, key);

    BOOST_CHECK_EQUAL(out, "69c4e0d86a7b0430d8cdb78070b4c55a");
}

BOOST_AUTO_TEST_CASE(rijndael_128_128_2) {

    std::string input = "00112233445566778899aabbccddeeff";
    std::string key = "000102030405060708090a0b0c0d0e0f";

    byte_string bk(key), bi(input);

    std::string out = encrypt<block::rijndael<128, 128>>(bi, bk);

    BOOST_CHECK_EQUAL(out, "69c4e0d86a7b0430d8cdb78070b4c55a");
}

BOOST_DATA_TEST_CASE(rijndael_128_128, string_data("key_128_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH (boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first);

        std::string out = encrypt<block::rijndael<128, 128>>(p, k);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}

 BOOST_DATA_TEST_CASE(rijndael_160_128, string_data("key_160_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first);

        std::string out = encrypt<block::rijndael<160, 128>>(p, k);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}


 BOOST_DATA_TEST_CASE(rijndael_192_128, string_data("key_192_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first);

        std::string out = encrypt<block::rijndael<192, 128>>(p, k);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}

 BOOST_DATA_TEST_CASE(rijndael_224_128, string_data("key_224_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first);

        std::string out = encrypt<block::rijndael<224, 128>>(p, k);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}

 BOOST_DATA_TEST_CASE(rijndael_256_128, string_data("key_256_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first);

        std::string out = encrypt<block::rijndael<256, 128>>(p, k);

        BOOST_CHECK_EQUAL(out, pair.second.data());
    }
}

BOOST_AUTO_TEST_SUITE_END()

/*  NIST SP 800-38A AES tests
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf */

BOOST_AUTO_TEST_SUITE(aes_stream_processor_test_suite)
// F.1.1, F.1.2
BOOST_AUTO_TEST_CASE(aes_128_cipher_usage) {

    std::string input =
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f"
        "\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41"
        "\x7b\xe6\x6c\x37\x10";

    std::string key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

    std::string out = encrypt<block::aes<128>>(input, key);

    BOOST_CHECK_EQUAL(out,
                      "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                      "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
}

BOOST_AUTO_TEST_CASE(aes_128_cipher) {

    std::string input =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    std::string key = "2b7e151628aed2a6abf7158809cf4f3c";

    byte_string bk(key), bi(input);

    std::string out = encrypt<block::aes<128>>(bi, bk);

    BOOST_CHECK_EQUAL(out,
                      "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                      "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
}

// F.1.3, F.1.4
BOOST_AUTO_TEST_CASE(aes_192_cipher) {
    std::string input =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    std::string key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";

    byte_string bk(key), bi(input);

    std::string out = encrypt<block::aes<192>>(bi, bk);

    BOOST_CHECK_EQUAL(out,
                      "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
                      "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");
}

// F.1.5, F.1.6
BOOST_AUTO_TEST_CASE(aes_256_cipher) {
    std::string input =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    std::string key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    byte_string bk(key), bi(input);

    std::string out = encrypt<block::aes<256>>(bi, bk);

    BOOST_CHECK_EQUAL(out,
                      "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
                      "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7");
}

BOOST_AUTO_TEST_SUITE_END()

/*
BOOST_AUTO_TEST_SUITE(aes_various_containers_test_suite)

BOOST_AUTO_TEST_CASE(aes_128_with_array_32) {

    std::array<uint32_t, 4> const k = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};
    std::array<uint32_t, 4> const p = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
    std::array<uint32_t, 4> const c = {0xd8e0c469, 0x30047b6a, 0x80b7cdd8, 0x5ac5b470};

    cipher_fixture<aes<128>, std::array<uint32_t, 4>, std::array<uint32_t, 4>> f(k, p, c);
    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(aes_128_with_array_16) {
    std::array<uint16_t, 8> const k = {0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e};
    std::array<uint16_t, 8> const p = {0x1100, 0x3322, 0x5544, 0x7766, 0x9988, 0xbbaa, 0xddcc, 0xffee};
    std::array<uint16_t, 8> const c = {0xc469, 0xd8e0, 0x7b6a, 0x3004, 0xcdd8, 0x80b7, 0xb470, 0x5ac5};

    cipher_fixture<aes<128>, std::array<uint16_t, 8>, std::array<uint16_t, 8>> f(k, p, c);
    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(aes_128_with_array_8) {
    std::array<uint8_t, 16> const k = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                       0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::array<uint8_t, 16> const p = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
                                       0xbb, 0xcc, 0xdd, 0xee, 0xff};
    std::array<uint8_t, 16> const c = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7,
                                       0x80, 0x70, 0xb4, 0xc5, 0x5a};

    cipher_fixture<aes<128>, std::array<uint8_t, 16>, std::array<uint8_t, 16>> f(k, p, c);
    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_SUITE_END()*/