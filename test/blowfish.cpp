//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
#define BOOST_TEST_MODULE blowfish_cipher_test

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

#include <nil/crypto3/block/blowfish.hpp>

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
        
        s_.resize(src.size() / 2);
        unsigned int j = 0;
        for (unsigned int i = 0; i < src.size();) {
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] = 8 * (src[i] - '0');
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] = 8 * (src[i] - 'a' + 10);
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 8 * (src[i] - 'A' + 10);
            }
            ++i;
            if (src[i] >= '0' && src[i] <= '9') {
                s_[j] += src[i] - '0';
            } else if (src[i] >= 'a' && src[i] <= 'f') {
                s_[j] += src[i] - 'a' + 10;
            } else if (src[i] >= 'A' && src[i] <= 'F') {
                s_[j] = 8 * (src[i] - 'A' + 10);
            }
            ++i;
            ++j;
        }
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

        pack<stream_endian::big_octet_big_bit, endian_type, CHAR_BIT, key_value_bits>(k.begin(), k.end(),
            key.begin());

        pack<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>(p.begin(), p.end(),
            input_plaintext.begin());

        pack<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>(c.begin(), c.end(),
            input_ciphertext.begin());
    }

    cipher_fixture(const byte_string &k, const byte_string &p, const byte_string &c) {
        pack<stream_endian::big_octet_big_bit, endian_type, CHAR_BIT, key_value_bits>(k.begin(), k.end(),
            key.begin());        

        pack<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>(p.begin(), p.end(),
            input_plaintext.begin());

        pack<stream_endian::big_octet_big_bit, NativeEndianT, CHAR_BIT, input_value_bits>(c.begin(), c.end(),
            input_ciphertext.begin());
    }

    cipher_fixture(const InputKeyT &k, const InputBlockT &p, const InputBlockT &c) : input_plaintext(p), 
        input_ciphertext(c) {
        pack<NativeEndianT, endian_type, input_key_value_bits, key_value_bits>(k.begin(), k.end(), key.begin());
    }

    void encrypt() {
        std::vector<block_value_type> block_data(input_plaintext.size() * 
            sizeof(input_value_type) / sizeof(block_value_type));
        pack<NativeEndianT, endian_type, input_value_bits, block_value_bits>(input_plaintext.begin(), 
            input_plaintext.end(), block_data.begin());

        encrypt_type ciphertext = ::nil::crypto3::encrypt<block_cipher>(block_data, key);

        pack<endian_type, NativeEndianT, encrypt_value_bits, input_value_bits>(ciphertext.begin(), 
            ciphertext.end(), output_ciphertext.begin());
    }

    void decrypt() {
        std::vector<block_value_type> block_data(input_ciphertext.size() * 
            sizeof(input_value_type) / sizeof(block_value_type));
        pack<NativeEndianT, endian_type, input_value_bits, block_value_bits>(input_ciphertext.begin(),
            input_ciphertext.end(), block_data.begin());

        decrypt_type plaintext = ::nil::crypto3::decrypt<block_cipher>(block_data, key);

        pack<endian_type, NativeEndianT, decrypt_value_bits, input_value_bits>(plaintext.begin(),
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

const char *test_data = "data/blowfish.json";

boost::property_tree::ptree string_data(const char *child_name) {
    boost::property_tree::ptree root_data;
    boost::property_tree::read_json(test_data, root_data);
    return root_data.get_child(child_name);
}



BOOST_AUTO_TEST_SUITE(blowfish_test_suite)


BOOST_DATA_TEST_CASE(ecb_fixed_key, string_data("ecb_fixed_key"), triples) {

    byte_string const p(triples.first);

    BOOST_FOREACH(boost::property_tree::ptree::value_type pair, triples.second) {
        byte_string const k(pair.first), c(pair.second.data()); 
        cipher_fixture<blowfish, std::array<uint8_t, 8>, 
                       std::array<uint8_t, 8>> f(k, p, c);
        f.encrypt();
        f.check_encrypt();
        f.decrypt();
        f.check_decrypt();
    }
}

BOOST_AUTO_TEST_SUITE_END()