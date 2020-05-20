//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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


template<typename BlockCipher, typename InputKeyT, typename InputBlockT,  
         typename NativeEndianT = stream_endian::little_octet_big_bit>
class cipher_fixture {

    typedef BlockCipher block_cipher;
    typedef typename block_cipher::key_type key_type;
    typedef typename block_cipher::endian_type endian_type;

    typedef typename InputBlockT::value_type input_value_type;
    typedef typename block_cipher::block_type::value_type block_value_type;

    typedef typename block::detail::range_cipher_impl<block::detail::value_cipher_impl
    <typename block::accumulator_set<typename block::modes::isomorphic<block_cipher, 
    nop_padding>::template bind<encryption_policy<block_cipher>>::type>>>::result_type encrypt_type;

    typedef typename block::detail::range_cipher_impl<block::detail::value_cipher_impl
    <typename block::accumulator_set<typename block::modes::isomorphic<block_cipher, 
    nop_padding>::template bind<decryption_policy<block_cipher>>::type>>>::result_type decrypt_type;

    constexpr static std::size_t const input_value_bits = sizeof(input_value_type) * CHAR_BIT;
    constexpr static std::size_t const input_key_value_bits = sizeof(typename InputKeyT::value_type) * CHAR_BIT;
    constexpr static std::size_t const block_value_bits = sizeof(block_value_type) * CHAR_BIT;
    constexpr static std::size_t const key_value_bits = sizeof(typename key_type::value_type) * CHAR_BIT; 
    constexpr static std::size_t const encrypt_value_bits = sizeof(typename encrypt_type::value_type) * CHAR_BIT;
    constexpr static std::size_t const decrypt_value_bits = sizeof(typename decrypt_type::value_type) * CHAR_BIT;

public:

    cipher_fixture(const char *ck, const char *cp, const char *cc) {
        byte_string const k(ck), p(cp), c(cc);

        packer<stream_endian::big_octet_big_bit, endian_type, CHAR_BIT, key_value_bits>::pack(k.begin(), 
            k.end(), key.begin());

        packer<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>::pack(p.begin(), 
            p.end(), input_plaintext.begin());

        packer<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>::pack(c.begin(), 
            c.end(), input_ciphertext.begin());
    }

    cipher_fixture(const byte_string &k, const byte_string &p, const byte_string &c) {
        packer<stream_endian::big_octet_big_bit, endian_type, CHAR_BIT, key_value_bits>::pack(k.begin(), 
            k.end(), key.begin());        

        packer<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>::pack(p.begin(), 
            p.end(), input_plaintext.begin());

        packer<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>::pack(c.begin(), 
            c.end(), input_ciphertext.begin());
    }

    cipher_fixture(const InputKeyT &k, const InputBlockT &p, const InputBlockT &c) : input_plaintext(p), 
        input_ciphertext(c) {
        packer<NativeEndianT, endian_type, input_key_value_bits, key_value_bits>::pack(k.begin(), k.end(), 
            key.begin());
    }

    void encrypt() {
        std::vector<block_value_type> block_data(input_plaintext.size() * 
            sizeof(input_value_type) / sizeof(block_value_type));
        packer<NativeEndianT, endian_type, input_value_bits, block_value_bits>::pack(input_plaintext.begin(), 
            input_plaintext.end(), block_data.begin());

        encrypt_type ciphertext = ::nil::crypto3::encrypt<block_cipher>(block_data, key);

        packer<endian_type, NativeEndianT, encrypt_value_bits, input_value_bits>::pack(ciphertext.begin(), 
            ciphertext.end(), output_ciphertext.begin());
    }

    void decrypt() {
        std::vector<block_value_type> block_data(input_ciphertext.size() * 
            sizeof(input_value_type) / sizeof(block_value_type));
        packer<NativeEndianT, endian_type, input_value_bits, block_value_bits>::pack(input_ciphertext.begin(),
            input_ciphertext.end(), block_data.begin());

        decrypt_type plaintext = ::nil::crypto3::decrypt<block_cipher>(block_data, key);

        packer<endian_type, NativeEndianT, decrypt_value_bits, input_value_bits>::pack(plaintext.begin(),
            plaintext.end(), output_plaintext.begin());
    }

    void check_encrypt() const {
        BOOST_ASSERT(input_ciphertext == output_ciphertext);
    }

    void check_decrypt() const {
        BOOST_ASSERT(input_plaintext == output_plaintext);
    }

private:

    key_type key;
    InputBlockT input_plaintext, input_ciphertext;
    InputBlockT output_plaintext, output_ciphertext;
};

const char *test_data = "data/rijndael.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    return root_data.get_child(child_name);
}


BOOST_AUTO_TEST_SUITE(rijndael_stream_processor_filedriven_test_suite)

BOOST_DATA_TEST_CASE(rijndael_128_128, string_data("key_128_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<rijndael<128, 128>, std::array<uint8_t, 16>, 
                       std::array<uint8_t, 16>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_DATA_TEST_CASE(rijndael_160_128, string_data("key_160_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<rijndael<160, 128>, std::array<uint8_t, 20>, 
                       std::array<uint8_t, 16>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_DATA_TEST_CASE(rijndael_192_128, string_data("key_192_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<rijndael<192, 128>, std::array<uint16_t, 12>, 
                       std::array<uint8_t, 16>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_DATA_TEST_CASE(rijndael_224_128, string_data("key_224_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<rijndael<224, 128>, std::array<uint32_t, 7>, 
                       std::array<uint8_t, 16>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_DATA_TEST_CASE(rijndael_256_128, string_data("key_256_block_128"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<rijndael<256, 128>, std::array<uint64_t, 4>, 
                       std::array<uint8_t, 16>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_AUTO_TEST_SUITE_END()

/*  NIST SP 800-38A AES tests 
    https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf */
BOOST_AUTO_TEST_SUITE(aes_stream_processor_test_suite)
// F.1.1, F.1.2
BOOST_AUTO_TEST_CASE(aes_128_cipher) {
    cipher_fixture<aes<128>, std::array<uint8_t, 16>, std::array<uint8_t, 64>>
    f("2b7e151628aed2a6abf7158809cf4f3c", 
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 
      "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
      "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// F.1.3, F.1.4
BOOST_AUTO_TEST_CASE(aes_192_cipher) {
    cipher_fixture<aes<192>, std::array<uint16_t, 12>, std::array<uint16_t, 32>>
    f("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 
      "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
      "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// F.1.5, F.1.6
BOOST_AUTO_TEST_CASE(aes_256_cipher) {
    cipher_fixture<aes<256>, std::array<uint32_t, 8>, std::array<uint32_t, 16>>
    f("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 
      "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
      "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_SUITE_END() 


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

BOOST_AUTO_TEST_CASE(aes_128_with_string) {
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

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(rijndael_stream_processor_test_suite)
// B = 128
BOOST_AUTO_TEST_CASE(rijndael_128_128_cipher) {
    cipher_fixture<rijndael<128, 128>, std::array<uint8_t, 16>, std::array<uint8_t, 16>>
    f("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", 
      "69c4e0d86a7b0430d8cdb78070b4c55a");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_160_128_cipher) {
    cipher_fixture<rijndael<160, 128>, std::array<uint8_t, 20>, std::array<uint8_t, 16>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160", "3243f6a8885a308d313198a2e0370734",
      "231d844639b31b412211cfe93712b880");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_192_128_cipher) {
    cipher_fixture<rijndael<192, 128>, std::array<uint16_t, 12>, std::array<uint8_t, 16>>
    f("000102030405060708090a0b0c0d0e0f1011121314151617", 
      "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_224_128_cipher) {
    cipher_fixture<rijndael<224, 128>, std::array<uint32_t, 7>, std::array<uint8_t, 16>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", 
      "3243f6a8885a308d313198a2e0370734", "8faa8fe4dee9eb17caa4797502fc9d3f");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_256_128_cipher) {
    cipher_fixture<rijndael<256, 128>, std::array<uint64_t, 4>, std::array<uint8_t, 16>> 
    f("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 
      "00112233445566778899aabbccddeeff","8ea2b7ca516745bfeafc49904b496089");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// B = 160
BOOST_AUTO_TEST_CASE(rijndael_128_160_cipher) {
    cipher_fixture<rijndael<128, 160>, std::array<uint8_t, 16>, std::array<uint16_t, 10>> 
    f("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e03707344a409382",
      "16e73aec921314c29df905432bc8968ab64b1f51");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_160_160_cipher) {
    cipher_fixture<rijndael<160, 160>, std::array<uint16_t, 10>, std::array<uint16_t, 10>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160", 
      "3243f6a8885a308d313198a2e03707344a409382","0553eb691670dd8a5a5b5addf1aa7450f7a0e587");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_192_160_cipher) {
    cipher_fixture<rijndael<192, 160>, std::array<uint16_t, 12>, std::array<uint16_t, 10>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", 
      "3243f6a8885a308d313198a2e03707344a409382", "73cd6f3423036790463aa9e19cfcde894ea16623");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_224_160_cipher) {
    cipher_fixture<rijndael<224, 160>, std::array<uint32_t, 7>, std::array<uint16_t, 10>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", 
      "3243f6a8885a308d313198a2e03707344a409382",
      "601b5dcd1cf4ece954c740445340bf0afdc048df");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_256_160_cipher) {
    cipher_fixture<rijndael<256, 160>, std::array<uint64_t, 4>, std::array<uint16_t, 10>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
      "3243f6a8885a308d313198a2e03707344a409382", "579e930b36c1529aa3e86628bacfe146942882cf");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// B = 192
BOOST_AUTO_TEST_CASE(rijndael_128_192_cipher) {
    cipher_fixture<rijndael<128, 192>, std::array<uint8_t, 16>, std::array<uint32_t, 6>> 
    f("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e03707344a4093822299f31d",
      "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_160_192_cipher) {
    cipher_fixture<rijndael<160, 192>, std::array<uint16_t, 10>, std::array<uint32_t, 6>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d", 
      "738dae25620d3d3beff4a037a04290d73eb33521a63ea568");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_192_192_cipher) {
    cipher_fixture<rijndael<192, 192>, std::array<uint32_t, 6>, std::array<uint32_t, 6>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d",
      "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_224_192_cipher) {
    cipher_fixture<rijndael<224, 192>, std::array<uint32_t, 7>, std::array<uint32_t, 6>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d", 
      "bbfc14180afbf6a36382a061843f0b63e769acdc98769130");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_256_192_cipher) {
    cipher_fixture<rijndael<256, 192>, std::array<uint64_t, 4>, std::array<uint32_t, 6>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d", 
      "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// B = 224
BOOST_AUTO_TEST_CASE(rijndael_128_224_cipher) {
    cipher_fixture<rijndael<128, 224>, std::array<uint8_t, 16>, std::array<uint32_t, 7>> 
    f("2b7e151628aed2a6abf7158809cf4f3c", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
      "b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_160_224_cipher) {
    cipher_fixture<rijndael<160, 224>, std::array<uint16_t, 10>, std::array<uint32_t, 7>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
      "08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_192_224_cipher) {
    cipher_fixture<rijndael<192, 224>, std::array<uint32_t, 6>, std::array<uint32_t, 7>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
      "be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_224_224_cipher) {
    cipher_fixture<rijndael<224, 224>, std::array<uint32_t, 7>, std::array<uint32_t, 7>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
      "ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_256_224_cipher) {
    cipher_fixture<rijndael<256, 224>, std::array<uint64_t, 4>, std::array<uint32_t, 7>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
      "02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

// B = 256
BOOST_AUTO_TEST_CASE(rijndael_128_256_cipher) {
    cipher_fixture<rijndael<128, 256>, std::array<uint8_t, 16>, std::array<uint64_t, 4>> 
    f("2b7e151628aed2a6abf7158809cf4f3c", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
      "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_160_256_cipher) {
    cipher_fixture<rijndael<160, 256>, std::array<uint16_t, 10>, std::array<uint64_t, 4>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
      "514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_192_256_cipher) {
    cipher_fixture<rijndael<192, 256>, std::array<uint64_t, 3>, std::array<uint64_t, 4>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5", 
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
      "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_224_256_cipher) {
    cipher_fixture<rijndael<224, 256>, std::array<uint32_t, 7>, std::array<uint64_t, 4>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
      "d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_CASE(rijndael_256_256_cipher) {
    cipher_fixture<rijndael<256, 256>, std::array<uint64_t, 4>, std::array<uint64_t, 4>> 
    f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
      "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
      "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a");

    f.encrypt();
    f.check_encrypt();
    f.decrypt();
    f.check_decrypt();
}

BOOST_AUTO_TEST_SUITE_END()