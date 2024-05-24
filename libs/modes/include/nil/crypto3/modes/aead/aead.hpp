//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MODE_AEAD_MODE_HPP
#define CRYPTO3_MODE_AEAD_MODE_HPP

#include <memory>

#include <boost/integer.hpp>

#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    struct authenticated_encryption_associated_data_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        template<typename T>
                        using allocator_type = Allocator<T>;

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;
                    };

                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    using aead_policy = authenticated_encryption_associated_data_policy<Cipher, Padding, Allocator>;

                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    struct authenticated_encryption_associated_data_encryption_policy
                        : public aead_policy<Cipher, Padding, Allocator> {

                        typedef aead_policy<Cipher, Padding, Allocator> policy_type;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    using aead_encryption_policy =
                        authenticated_encryption_associated_data_encryption_policy<Cipher, Padding, Allocator>;

                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    struct authenticated_encryption_associated_data_decryption_policy
                        : public aead_policy<Cipher, Padding, Allocator> {

                        typedef aead_policy<Cipher, Padding, Allocator> policy_type;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, template<typename> class Allocator>
                    using aead_decryption_policy =
                        authenticated_encryption_associated_data_decryption_policy<Cipher, Padding, Allocator>;

                    template<typename Policy>
                    class authenticated_encryption_associated_data {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename cipher_type::key_type key_type;
                        typedef typename policy_type::authenticated_data_type authenticated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        authenticated_encryption_associated_data(const cipher_type &cipher,
                                                                 const AssociatedDataContainer &associated_data) :
                            cipher(cipher) {
                            schedule_associated_data(associated_data);
                        }

                        block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext, ad);
                        }

                        block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(cipher, plaintext, ad);
                        }

                        block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext, ad);
                        }

                        inline static std::size_t required_output_size(std::size_t inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        template<typename AssociatedDataContainer>
                        inline void schedule_associated_data(const AssociatedDataContainer &iad) {
                            pack(iad, ad);
                        }

                        authenticated_data_type ad;

                        cipher_type cipher;
                    };

                    template<typename Policy>
                    using aead = authenticated_encryption_associated_data<Policy>;
                }    // namespace detail

                /*!
                 * @brief Interface for AEAD (Authenticated Encryption with Associated Data)
                 * modes. These modes provide both encryption and message
                 * authentication, and can authenticate additional per-message data
                 * which is not included in the ciphertext (for instance a sequence
                 * number).
                 *
                 * @tparam Cipher
                 * @tparam Padding
                 * @tparam Allocator
                 */
                template<typename Cipher,
                         template<typename>
                         class Padding,
                         template<typename> class Allocator = std::allocator>
                struct authenticated_encryption_associated_data {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;

                    template<typename T>
                    using allocator_type = Allocator<T>;

                    typedef detail::aead_encryption_policy<cipher_type, padding_type, allocator_type> encryption_policy;
                    typedef detail::aead_decryption_policy<cipher_type, padding_type, allocator_type> decryption_policy;

                    template<template<typename, typename, template<typename> class> class Policy>
                    struct bind {
                        typedef detail::authenticated_encryption_associated_data<
                            Policy<cipher_type, padding_type, allocator_type>>
                            type;
                    };
                };

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 * @tparam Allocator
                 */
                template<typename Cipher,
                         template<typename>
                         class Padding,
                         template<typename> class Allocator = std::allocator>
                using aead = authenticated_encryption_associated_data<Cipher, Padding, Allocator>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
