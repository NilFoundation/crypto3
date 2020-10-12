//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_MODE_EAD_SIV_HPP
#define CRYPTO3_STREAM_MODE_EAD_SIV_HPP

#include <nil/crypto3/detail/poly_dbl.hpp>

#include <nil/crypto3/modes/aead/aead.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename BlockCipher>
            struct cmac;
        }

        namespace stream {
            template<typename BlockCipher, std::size_t CtrBits = BlockCipher::block_bits>
            class ctr;
        }

        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, std::size_t TagBits, typename StreamCipher,
                             typename MessageAuthenticationCode, template<typename> class Allocator>
                    struct siv_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;
                        typedef StreamCipher stream_cipher_type;
                        typedef MessageAuthenticationCode mac_type;

                        template<typename T>
                        using allocator_type = Allocator<T>;

                        constexpr static const std::size_t tag_bits = TagBits;

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits == 128);

                        constexpr static const std::size_t key_bits = stream_cipher_type::key_bits + mac_type::key_bits;
                        constexpr static const std::size_t key_size = key_bits / CHAR_BIT;
                        typedef std::array<std::uint8_t, key_size> key_type;

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;
                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>> nonce_type;

                        inline static block_type begin_message(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            if (nonce_len) {
                                m_nonce = m_mac->process(nonce, nonce_len);
                            } else {
                                m_nonce.clear();
                            }

                            m_msg_buf.clear();

                            return cipher.encrypt(block);
                        }

                        static void S2V(const mac_type &mac, const uint8_t *text, size_t text_len) {
                            using namespace nil::crypto3::detail;

                            const std::vector<uint8_t> zeros(block_size());

                            secure_vector<uint8_t> V = mac->process(zeros.data(), zeros.size());

                            for (size_t i = 0; i != m_ad_macs.size(); ++i) {
                                poly_double_n(V.data(), V.size());
                                V ^= m_ad_macs[i];
                            }

                            if (m_nonce.size()) {
                                poly_double_n(V.data(), V.size());
                                V ^= m_nonce;
                            }

                            if (text_len < block_size()) {
                                poly_double_n(V.data(), V.size());
                                xor_buf(V.data(), text, text_len);
                                V[text_len] ^= 0x80;
                                return mac->process(V);
                            }

                            mac->update(text, text_len - block_size());
                            xor_buf(V.data(), &text[text_len - block_size()], block_size());
                            mac->update(V);

                            return mac->final();
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t TagBits, typename StreamCipher,
                             typename MessageAuthenticationCode, template<typename> class Allocator>
                    class siv_encryption_policy : public siv_policy<Cipher, Padding, TagBits, StreamCipher,
                                                                    MessageAuthenticationCode, Allocator> {
                        typedef siv_policy<Cipher, Padding, TagBits, StreamCipher, MessageAuthenticationCode, Allocator>
                            policy_type;

                    public:
                        template<typename T>
                        using allocator_type = typename policy_type::template allocator_type<T>;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename policy_type::key_type key_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const stream_cipher_type &cipher,
                                                             const block_type &plaintext) {
                            block_type result = {0};

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");

                            buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
                            msg_buf().clear();

                            const secure_vector<uint8_t> V = S2V(buffer.data() + offset, buffer.size() - offset);

                            buffer.insert(buffer.begin() + offset, V.begin(), V.end());

                            if (buffer.size() != offset + V.size()) {
                                set_ctr_iv(V);
                                ctr().cipher1(&buffer[offset + V.size()], buffer.size() - offset - V.size());
                            }

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t TagBits, typename StreamCipher,
                             typename MessageAuthenticationCode, template<typename> class Allocator = std::allocator>
                    class siv_decryption_policy : public siv_policy<Cipher, Padding, TagBits, StreamCipher,
                                                                    MessageAuthenticationCode, Allocator> {
                        typedef siv_policy<Cipher, Padding, TagBits, StreamCipher, MessageAuthenticationCode, Allocator>
                            policy_type;

                    public:
                        template<typename T>
                        using allocator_type = typename policy_type::template allocator_type<T>;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename policy_type::key_type key_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const stream_cipher_type &cipher,
                                                             const block_type &plaintext) {
                            block_type result = {0};

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");

                            if (msg_buf().size() > 0) {
                                buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
                                msg_buf().clear();
                            }

                            const size_t sz = buffer.size() - offset;

                            BOOST_ASSERT_MSG(sz >= tag_size(), "We have the tag");

                            secure_vector<uint8_t> V(buffer.data() + offset, buffer.data() + offset + block_size());

                            if (buffer.size() != offset + V.size()) {
                                set_ctr_iv(V);

                                ctr().cipher(buffer.data() + offset + V.size(), buffer.data() + offset,
                                             buffer.size() - offset - V.size());
                            }

                            const secure_vector<uint8_t> T =
                                S2V(buffer.data() + offset, buffer.size() - offset - V.size());

                            if (!constant_time_compare(T.data(), V.data(), T.size())) {
                                throw integrity_failure("SIV tag check failed");
                            }

                            buffer.resize(buffer.size() - tag_size());

                            return result;
                        }
                    };

                    template<typename Policy>
                    class siv {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        constexpr static const std::size_t key_bits = policy_type::key_bits;
                        constexpr static const std::size_t key_size = policy_type::key_size;
                        typedef typename policy_type::key_type key_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        siv(const stream_cipher_type &stream_cipher, const mac_type &mac, const nonce_type &nonce,
                            const AssociatedDataContainer &associated_data) :
                            stream_cipher(stream_cipher),
                            mac(mac) {
                            schedule_associated_data(associated_data);

                            V[m_bs - 8] &= 0x7F;
                            V[m_bs - 4] &= 0x7F;

                            ctr().set_iv(V.data(), V.size());
                        }

                        template<typename AssociatedDataContainer>
                        siv(const key_type &key, const nonce_type &nonce,
                            const AssociatedDataContainer &associated_data) :
                            stream_cipher({key.begin() + key_size / 2, key.end()}),
                            mac({key.begin(), key.begin() + key_size / 2}) {
                            schedule_associated_data(associated_data);

                            V[m_bs - 8] &= 0x7F;
                            V[m_bs - 4] &= 0x7F;

                            ctr().set_iv(V.data(), V.size());
                        }

                        inline block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(stream_cipher, plaintext, ad);
                        }

                        inline block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(stream_cipher, plaintext, ad);
                        }

                        inline block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(stream_cipher, plaintext, ad);
                        }

                        inline static std::size_t required_output_size(std::size_t inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        template<typename AssociatedDataContainer>
                        inline void schedule_associated_data(const AssociatedDataContainer &iad) {
                        }

                        nonce_type nonce;
                        std::vector<associated_data_type> ad_macs;

                        stream_cipher_type stream_cipher;
                        mac_type mac;
                    };
                }    // namespace detail

                /*!
                 * @brief SIV encryption and decryption (@see RFC 5297)
                 *
                 * @tparam BlockCipher
                 * @tparam Padding
                 * @tparam StreamCipher
                 * @tparam MessageAuthenticationCode
                 */
                template<typename BlockCipher, template<typename> class Padding, std::size_t TagBits = 16 * CHAR_BIT,
                         typename StreamCipher = stream::ctr<BlockCipher>,
                         typename MessageAuthenticationCode = mac::cmac<BlockCipher>,
                         template<typename> class Allocator = std::allocator>
                struct siv {
                    typedef BlockCipher cipher_type;
                    typedef Padding<BlockCipher> padding_type;
                    typedef StreamCipher stream_cipher_type;
                    typedef MessageAuthenticationCode mac_type;

                    template<typename T>
                    using allocator_type = Allocator<T>;

                    typedef detail::siv_encryption_policy<cipher_type, padding_type, TagBits, stream_cipher_type,
                                                          mac_type, allocator_type>
                        encryption_policy;
                    typedef detail::siv_decryption_policy<cipher_type, padding_type, TagBits, stream_cipher_type,
                                                          mac_type, allocator_type>
                        decryption_policy;

                    template<template<typename, typename, std::size_t, typename, typename, template<typename> class>
                             class Policy>
                    struct bind {
                        typedef detail::siv<
                            Policy<cipher_type, padding_type, TagBits, stream_cipher_type, mac_type, allocator_type>>
                            type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
