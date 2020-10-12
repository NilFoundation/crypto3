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

#ifndef CRYPTO3_MODES_AEAD_CCM_HPP
#define CRYPTO3_MODES_AEAD_CCM_HPP

#include <nil/crypto3/detail/make_uint_t.hpp>

#include <nil/crypto3/modes/aead/aead.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, std::size_t NonceBits,
                             std::size_t TagBits = 16 * CHAR_BIT, std::size_t LengthBits = 3 * CHAR_BIT,
                             template<typename> class Allocator = std::allocator>
                    struct ccm_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const std::size_t tag_bits = TagBits;
                        constexpr static const std::size_t length_bits = LengthBits;

                        BOOST_STATIC_ASSERT(length_bits >= 2 && length_bits <= 8);
                        BOOST_STATIC_ASSERT(tag_bits >= 4 * CHAR_BIT && tag_bits <= 16 * CHAR_BIT);
                        BOOST_STATIC_ASSERT(tag_bits % 2);

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits == 128);

                        constexpr static const std::size_t min_nonce_bits = 0;
                        constexpr static const std::size_t max_nonce_bits = 15 * CHAR_BIT - length_bits;
                        constexpr static const std::size_t nonce_bits = NonceBits;
                        constexpr static const std::size_t nonce_size = nonce_bits / CHAR_BIT;
                        typedef std::array<std::uint8_t, nonce_size> nonce_type;

                        BOOST_STATIC_ASSERT(nonce_bits >= min_nonce_bits && nonce_bits <= max_nonce_bits);

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;

                        template<typename Container>
                        inline static void inc(Container &C) {
                            for (size_t i = 0; i != C.size(); ++i) {
                                if (++C[C.size() - i - 1]) {
                                    break;
                                }
                            }
                        }

                        inline static void encode_length(std::size_t len, uint8_t out[]) {
                            using namespace nil::crypto3::detail;

                            const size_t len_bytes = length_bits / CHAR_BIT;

                            BOOST_ASSERT_MSG(len_bytes < sizeof(size_t), "Length field fits");

                            for (size_t i = 0; i != len_bytes; ++i) {
                                out[len_bytes - 1 - i] = extract_uint_t<CHAR_BIT>(len, sizeof(size_t) - 1 - i);
                            }

                            BOOST_ASSERT_MSG((len >> (len_bytes * 8)) == 0, "Message length fits in field");
                        }

                        inline static block_type format_b0(const associated_data_type &ad, const nonce_type &nonce,
                                                           size_t sz) {
                            block_type b0 = {static_cast<uint8_t>((ad.size() ? 64 : 0) +
                                                                  ((tag_bits / 2 * CHAR_BIT - 1) << 3U) +
                                                                  (length_bits / CHAR_BIT - 1))};

                            copy_mem(&b0[1], nonce.data(), nonce.size());
                            encode_length(sz, &b0[nonce.size() + 1]);

                            return b0;
                        }

                        inline static block_type format_c0(const nonce_type &nonce) {
                            block_type c = {static_cast<uint8_t>(length_bits / CHAR_BIT - 1)};
                            copy_mem(&c[1], nonce.data(), nonce.size());

                            return c;
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t NonceBits,
                             std::size_t TagBits = 16 * CHAR_BIT, std::size_t LengthBits = 3 * CHAR_BIT,
                             template<typename> class Allocator = std::allocator>
                    struct ccm_encryption_policy
                        : public ccm_policy<Cipher, Padding, NonceBits, TagBits, LengthBits, Allocator> {
                        typedef ccm_policy<Cipher, Padding, NonceBits, TagBits, LengthBits, Allocator> policy_type;

                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                        constexpr static const std::size_t tag_bits = policy_type::tag_bits;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        constexpr static const std::size_t nonce_bits = policy_type::nonce_bits;
                        typedef typename policy_type::nonce_type nonce_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return plaintext;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return plaintext;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");

                            buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            const secure_vector<uint8_t> &ad = ad_buf();
                            BOOST_ASSERT_MSG(ad.size() % CCM_BS == 0, "AD is block size multiple");

                            secure_vector<uint8_t> T(CCM_BS);
                            cipher.encrypt(policy_type::format_b0(sz), T);

                            for (size_t i = 0; i != ad.size(); i += CCM_BS) {
                                xor_buf(T.data(), &ad[i], CCM_BS);
                                cipher.encrypt(T);
                            }

                            secure_vector<uint8_t> C = policy_type::format_c0();
                            secure_vector<uint8_t> S0(CCM_BS);
                            cipher.encrypt(C, S0);
                            policy_type::inc(C);

                            secure_vector<uint8_t> X(CCM_BS);

                            const uint8_t *buf_end = &buf[sz];

                            while (buf != buf_end) {
                                const size_t to_proc = std::min<size_t>(CCM_BS, buf_end - buf);

                                xor_buf(T.data(), buf, to_proc);
                                cipher.encrypt(T);

                                cipher.encrypt(C, X);
                                xor_buf(buf, X.data(), to_proc);
                                policy_type::inc(C);

                                buf += to_proc;
                            }

                            T ^= S0;

                            buffer += std::make_pair(T.data(), tag_bits / CHAR_BIT);

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t NonceBits,
                             std::size_t TagBits = 16 * CHAR_BIT, std::size_t LengthBits = 3 * CHAR_BIT,
                             template<typename> class Allocator = std::allocator>
                    struct ccm_decryption_policy
                        : public ccm_policy<Cipher, Padding, NonceBits, TagBits, LengthBits, Allocator> {

                        typedef ccm_policy<Cipher, Padding, NonceBits, TagBits, LengthBits, Allocator> policy_type;

                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                        constexpr static const std::size_t tag_bits = policy_type::tag_bits;

                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        constexpr static const std::size_t nonce_bits = policy_type::nonce_bits;
                        typedef typename policy_type::nonce_type nonce_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return plaintext;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return plaintext;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");

                            buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            BOOST_ASSERT_MSG(sz >= tag_size(), "We have the tag");

                            const secure_vector<uint8_t> &ad = ad_buf();
                            BOOST_ASSERT_MSG(ad.size() % CCM_BS == 0, "AD is block size multiple");

                            secure_vector<uint8_t> T(CCM_BS);
                            cipher.encrypt(format_b0(sz - tag_size()), T);

                            for (size_t i = 0; i != ad.size(); i += CCM_BS) {
                                xor_buf(T.data(), &ad[i], CCM_BS);
                                cipher.encrypt(T);
                            }

                            secure_vector<uint8_t> C = format_c0();

                            secure_vector<uint8_t> S0(CCM_BS);
                            cipher.encrypt(C, S0);
                            policy_type::inc(C);

                            secure_vector<uint8_t> X(CCM_BS);

                            const uint8_t *buf_end = &buf[sz - tag_size()];

                            while (buf != buf_end) {
                                const size_t to_proc = std::min<size_t>(CCM_BS, buf_end - buf);

                                cipher.encrypt(C, X);
                                xor_buf(buf, X.data(), to_proc);
                                policy_type::inc(C);

                                xor_buf(T.data(), buf, to_proc);
                                cipher.encrypt(T);

                                buf += to_proc;
                            }

                            T ^= S0;

                            if (!constant_time_compare(T.data(), buf_end, tag_size())) {
                                throw integrity_failure("CCM tag check failed");
                            }

                            buffer.resize(buffer.size() - tag_size());

                            return result;
                        }
                    };

                    template<typename Policy>
                    class ccm {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        constexpr static const std::size_t key_bits = cipher_type::key_bits;
                        typedef typename cipher_type::key_type key_type;

                        constexpr static const std::size_t nonce_bits = policy_type::nonce_bits;
                        typedef typename policy_type::nonce_type nonce_type;

                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        ccm(const cipher_type &cipher, const AssociatedDataContainer &associated_data,
                            const nonce_type &nonce) :
                            cipher(cipher) {
                            schedule_associated_data(associated_data);
                        }

                        template<typename AssociatedDataContainer>
                        ccm(const key_type &key, const AssociatedDataContainer &associated_data,
                            const nonce_type &nonce) :
                            cipher(key) {
                        }

                        inline block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext, ad);
                        }

                        inline block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(cipher, plaintext, ad);
                        }

                        inline block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext, ad);
                        }

                        inline static std::size_t required_output_size(std::size_t inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        template<typename AssociatedDataContainer>
                        inline void schedule_associated_data(const AssociatedDataContainer &input_ad) {
                            using namespace nil::crypto3::detail;

                            if (!input_ad.empty()) {
                                // FIXME: support larger AD using length encoding rules
                                BOOST_ASSERT_MSG(length < (0xFFFF - 0xFF), "Supported CCM AD length");

                                ad.push_back(extract_uint_t<CHAR_BIT>(static_cast<uint16_t>(length), 0));
                                ad.push_back(extract_uint_t<CHAR_BIT>(static_cast<uint16_t>(length), 1));
                                ad += std::make_pair(ad, length);
                                while (ad.size() % (block_bits / CHAR_BIT)) {
                                    ad.push_back(0);
                                }    // pad with zeros to full block size
                            }
                        }

                        associated_data_type ad;

                        cipher_type cipher;
                    };
                }    // namespace detail

                /*!
                 * @brief CCM encryption and decryption
                 * @see RFC 3610
                 * @tparam BlockCipher A 128-bit BlockCipher
                 * @tparam Padding
                 * @tparam TagBits Size of the authentication tag (even values between 4 and 16 are accepted)
                 * @tparam L length of L parameter. The total message length
                 * must be less than 2**L bytes, and the nonce is 15-L bytes.
                 */
                template<typename BlockCipher, template<typename> class Padding, std::size_t NonceBits,
                         std::size_t TagBits = 16 * CHAR_BIT, std::size_t LengthBits = 3 * CHAR_BIT,
                         template<typename> class Allocator = std::allocator>
                struct ccm {
                    typedef BlockCipher cipher_type;
                    typedef Padding<BlockCipher> padding_type;

                    typedef detail::ccm_encryption_policy<cipher_type, padding_type, NonceBits, TagBits, LengthBits,
                                                          Allocator>
                        encryption_policy;
                    typedef detail::ccm_decryption_policy<cipher_type, padding_type, NonceBits, TagBits, LengthBits,
                                                          Allocator>
                        decryption_policy;

                    template<
                        template<typename, typename, std::size_t, std::size_t, std::size_t, template<typename> class>
                        class Policy>
                    struct bind {
                        typedef detail::ccm<
                            Policy<cipher_type, padding_type, NonceBits, TagBits, LengthBits, Allocator>>
                            type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
