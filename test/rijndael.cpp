//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE rijndael_cipher_test

#include <iostream>
#include <unordered_map>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/algorithm/decrypt.hpp>

#include <nil/crypto3/block/rijndael.hpp>

using namespace nil::crypto3::block;

typedef std::unordered_map<std::string, std::string>::value_type string_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(string_data_value)

typedef std::unordered_map<std::string, std::vector<uint8_t>>::value_type byte_vector_data_value;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_data_value)

typedef std::vector<uint8_t> byte_vector_t;
BOOST_TEST_DONT_PRINT_LOG_VALUE(byte_vector_t)

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
        //const unsigned char* src = static_cast<const unsigned char*>(vsrc);
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

template<std::size_t K, std::size_t B>
struct cipher_fixture {
    cipher_fixture(const std::string &ckey, const std::string &cplaintext, const std::string &ccipher_text)
            : original_plaintext(cplaintext), original_cipher_text(ccipher_text), cipher_text(ccipher_text.size() / 2),
            plaintext(ccipher_text.size() / 2), c(key) {
        byte_string packed_string(ckey);
        pack<stream_endian::little_octet_big_bit, sizeof(byte_string::value_type) * CHAR_BIT,
                sizeof(typename rijndael<K, B>::key_type::value_type) * CHAR_BIT>(packed_string, key);
        c = rijndael<K, B>(key);
    }

    void encrypt() {
        typename rijndael<K, B>::block_type block, result;
        pack<stream_endian::little_octet_big_bit, sizeof(byte_string::value_type) * CHAR_BIT,
                sizeof(typename rijndael<K, B>::block_type::value_type) * CHAR_BIT>(original_plaintext, block);

        result = c.encrypt(block);

        pack<stream_endian::little_octet_big_bit, sizeof(typename rijndael<K, B>::block_type::value_type) * CHAR_BIT,
                sizeof(byte_string::value_type) * CHAR_BIT>(result, cipher_text);
    }

    void decrypt() {
        typename rijndael<K, B>::block_type block, result;
        pack<stream_endian::little_octet_big_bit, sizeof(byte_string::value_type) * CHAR_BIT,
                sizeof(typename rijndael<K, B>::block_type::value_type) * CHAR_BIT>(cipher_text, block);

        result = c.decrypt(block);
        pack<stream_endian::little_octet_big_bit, sizeof(typename rijndael<K, B>::block_type::value_type) * CHAR_BIT,
                sizeof(byte_string::value_type) * CHAR_BIT>(result, plaintext);
    }

    typename rijndael<K, B>::key_type key;
    const byte_string original_plaintext, original_cipher_text;
    byte_string cipher_text, plaintext;
    rijndael<K, B> c;
};

BOOST_AUTO_TEST_SUITE(rijndael_cipher_test_suite)

// B = 128
    BOOST_AUTO_TEST_CASE(rijndael_128_128_cipher) {
        cipher_fixture<128, 128> f("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
                "69c4e0d86a7b0430d8cdb78070b4c55a");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_160_128_cipher) {
        cipher_fixture<160, 128> f("2b7e151628aed2a6abf7158809cf4f3c762e7160", "3243f6a8885a308d313198a2e0370734",
                "231d844639b31b412211cfe93712b880");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_192_128_cipher) {
        cipher_fixture<192, 128> f("000102030405060708090a0b0c0d0e0f1011121314151617",
                "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_224_128_cipher) {
        cipher_fixture<224, 128> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
                "3243f6a8885a308d313198a2e0370734", "8faa8fe4dee9eb17caa4797502fc9d3f");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_256_128_cipher) {
        cipher_fixture<256, 128> f("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }


// B = 160
    BOOST_AUTO_TEST_CASE(rijndael_128_160_cipher) {
        cipher_fixture<128, 160> f("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e03707344a409382",
                "16e73aec921314c29df905432bc8968ab64b1f51");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_160_160_cipher) {
        cipher_fixture<160, 160> f("2b7e151628aed2a6abf7158809cf4f3c762e7160",
                "3243f6a8885a308d313198a2e03707344a409382", "0553eb691670dd8a5a5b5addf1aa7450f7a0e587");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_192_160_cipher) {
        cipher_fixture<192, 160> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
                "3243f6a8885a308d313198a2e03707344a409382", "73cd6f3423036790463aa9e19cfcde894ea16623");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_224_160_cipher) {
        cipher_fixture<224, 160> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
                "3243f6a8885a308d313198a2e03707344a409382", "601b5dcd1cf4ece954c740445340bf0afdc048df");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_256_160_cipher) {
        cipher_fixture<256, 160> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
                "3243f6a8885a308d313198a2e03707344a409382", "579e930b36c1529aa3e86628bacfe146942882cf");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }


// B = 192
    BOOST_AUTO_TEST_CASE(rijndael_128_192_cipher) {
        cipher_fixture<128, 192> f("2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d", "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_160_192_cipher) {
        cipher_fixture<160, 192> f("2b7e151628aed2a6abf7158809cf4f3c762e7160",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d", "738dae25620d3d3beff4a037a04290d73eb33521a63ea568");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_192_192_cipher) {
        cipher_fixture<192, 192> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d", "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_224_192_cipher) {
        cipher_fixture<224, 192> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d", "bbfc14180afbf6a36382a061843f0b63e769acdc98769130");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_256_192_cipher) {
        cipher_fixture<256, 192> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d", "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }


// B = 224
    BOOST_AUTO_TEST_CASE(rijndael_128_224_cipher) {
        cipher_fixture<128, 224> f("2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
                "b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_160_224_cipher) {
        cipher_fixture<160, 224> f("2b7e151628aed2a6abf7158809cf4f3c762e7160",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
                "08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_192_224_cipher) {
        cipher_fixture<192, 224> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
                "be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_224_224_cipher) {
        cipher_fixture<224, 224> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
                "ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_256_224_cipher) {
        cipher_fixture<256, 224> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9",
                "02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }


// B = 256
    BOOST_AUTO_TEST_CASE(rijndael_128_256_cipher) {
        cipher_fixture<128, 256> f("2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
                "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_160_256_cipher) {
        cipher_fixture<160, 256> f("2b7e151628aed2a6abf7158809cf4f3c762e7160",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
                "514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_192_256_cipher) {
        cipher_fixture<192, 256> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
                "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_224_256_cipher) {
        cipher_fixture<224, 256> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
                "d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

    BOOST_AUTO_TEST_CASE(rijndael_256_256_cipher) {
        cipher_fixture<256, 256> f("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe",
                "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8",
                "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a");

        f.encrypt();
        BOOST_CHECK_EQUAL(f.cipher_text, f.original_cipher_text);
        f.decrypt();
        BOOST_CHECK_EQUAL(f.plaintext, f.original_plaintext);
    }

BOOST_AUTO_TEST_SUITE_END()
