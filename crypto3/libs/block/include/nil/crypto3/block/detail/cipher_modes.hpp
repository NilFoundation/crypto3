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

#ifndef CRYPTO3_CIPHER_MODES_HPP
#define CRYPTO3_CIPHER_MODES_HPP

#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                template<typename Cipher, typename Padding>
                struct isomorphic_policy {
                    typedef std::size_t size_type;

                    typedef Cipher cipher_type;
                    typedef Padding padding_type;

                    constexpr static const size_type block_bits = cipher_type::block_bits;
                    constexpr static const size_type block_words = cipher_type::block_words;
                    typedef typename cipher_type::block_type block_type;

                    typedef typename cipher_type::endian_type endian_type;
                };

                template<typename Cipher, typename Padding>
                struct isomorphic_encryption_policy : public isomorphic_policy<Cipher, Padding> {
                    typedef typename isomorphic_policy<Cipher, Padding>::cipher_type cipher_type;
                    typedef typename isomorphic_policy<Cipher, Padding>::block_type block_type;

                    inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }

                    inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }

                    inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }
                };

                template<typename Cipher, typename Padding>
                struct isomorphic_decryption_policy : public isomorphic_policy<Cipher, Padding> {
                    typedef typename isomorphic_policy<Cipher, Padding>::cipher_type cipher_type;
                    typedef typename isomorphic_policy<Cipher, Padding>::block_type block_type;

                    inline static block_type begin_message(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }

                    inline static block_type process_block(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }

                    inline static block_type end_message(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }
                };

                template<typename Policy>
                class isomorphic {
                    typedef Policy policy_type;

                public:
                    typedef typename policy_type::cipher_type cipher_type;
                    typedef typename policy_type::padding_type padding_type;

                    typedef typename policy_type::size_type size_type;

                    typedef typename cipher_type::key_type key_type;

                    typedef typename policy_type::endian_type endian_type;

                    typedef typename cipher_type::block_type block_type;
                    typedef typename cipher_type::word_type word_type;

                    constexpr static const size_type block_bits = policy_type::block_bits;
                    constexpr static const size_type block_words = policy_type::block_words;
                    constexpr static const size_type word_bits = cipher_type::word_bits;

                    isomorphic(const cipher_type &cipher) : cipher(cipher) {
                    }

                    block_type begin_message(const block_type &plaintext, std::size_t total_seen) {
                        return policy_type::begin_message(cipher, plaintext);
                    }

                    block_type process_block(const block_type &plaintext, std::size_t total_seen) {
                        return policy_type::process_block(cipher, plaintext);
                    }

                    block_type end_message(const block_type &plaintext, std::size_t total_seen) const {
                        return policy_type::end_message(cipher, plaintext);
                    }

                protected:
                    cipher_type cipher;
                };
            }    // namespace detail

            namespace modes {

                template<typename Cipher, template<typename> class Padding>
                struct isomorphic {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;

                    typedef detail::isomorphic_encryption_policy<cipher_type, padding_type> encryption_policy;
                    typedef detail::isomorphic_decryption_policy<cipher_type, padding_type> decryption_policy;

                    template<typename Policy>
                    struct bind {
                        typedef detail::isomorphic<Policy> type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHER_MODES_HPP
